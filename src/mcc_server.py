#!/usr/bin/env python3
"""
Mission Control Center (MCC) Server
Multi-threaded server handling multiple drones with concurrent authentication
"""

import socket
import threading
import time
import hashlib
import json
from typing import Dict, Optional
from dataclasses import dataclass

import config
import utils
import crypto_utils
from crypto_utils import ElGamal, ElGamalKeyPair
from protocol import *


@dataclass
class DroneInfo:
    """Information about authenticated drone"""
    drone_id: str
    socket: socket.socket
    session_key: bytes
    public_key: Tuple[int, int, int]  # (p, g, y)
    timestamp_i: int
    nonce_i: bytes
    authenticated: bool = False


class MCCServer:
    """Mission Control Center Server"""
    
    def __init__(self, host: str = config.MCC_HOST, port: int = config.MCC_PORT):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        
        # Cryptographic parameters
        self.security_level = config.SECURITY_LEVEL
        self.p: Optional[int] = None
        self.g: Optional[int] = None
        self.keypair: Optional[ElGamalKeyPair] = None
        
        # Fleet registry (thread-safe)
        self.drones: Dict[str, DroneInfo] = {}
        self.drones_lock = threading.Lock()
        
        # Group key
        self.group_key: Optional[bytes] = None
        
        # Server state
        self.running = False
        self.accept_thread: Optional[threading.Thread] = None
        
        print(f"[MCC] Initializing Mission Control Center...")
        print(f"[MCC] Security Level: {self.security_level} bits")
    
    def initialize_crypto(self):
        """Initialize ElGamal parameters and keypair"""
        print(f"\n[MCC] Generating ElGamal parameters (SL={self.security_level})...")
        print("[MCC] This may take a few moments...")
        
        # Generate keypair (includes p and g generation)
        self.keypair = ElGamal.generate_keypair(self.security_level)
        self.p = self.keypair.p
        self.g = self.keypair.g
        
        print(f"[MCC] ✓ Prime p generated: {self.p.bit_length()} bits")
        print(f"[MCC] ✓ Generator g: {self.g}")
        print(f"[MCC] ✓ Public key y: {self.keypair.y.bit_length()} bits")
        print(f"[MCC] Cryptographic initialization complete!\n")
    
    def start(self):
        """Start MCC server"""
        # Initialize crypto first
        self.initialize_crypto()
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.running = True
        
        print(f"[MCC] Server started on {self.host}:{self.port}")
        print(f"[MCC] Waiting for drone connections...\n")
        
        # Start accept thread
        self.accept_thread = threading.Thread(target=self.accept_connections)
        self.accept_thread.daemon = True
        self.accept_thread.start()
    
    def accept_connections(self):
        """Accept incoming drone connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[MCC] New connection from {address}")
                
                # Spawn handler thread
                handler_thread = threading.Thread(
                    target=self.handle_drone,
                    args=(client_socket, address)
                )
                handler_thread.daemon = True
                handler_thread.start()
            
            except Exception as e:
                if self.running:
                    print(f"[MCC] Error accepting connection: {e}")
    
    def handle_drone(self, client_socket: socket.socket, address):
        """Handle individual drone connection"""
        drone_id = None
        
        try:
            # Phase 0: Parameter Initialization
            if not self.send_parameters(client_socket):
                print(f"[MCC] Failed to send parameters to {address}")
                return
            
            # Phase 1: Mutual Authentication
            drone_id, drone_info = self.authenticate_drone(client_socket, address)
            if not drone_id:
                print(f"[MCC] Authentication failed for {address}")
                return
            
            # Phase 2: Session Key Confirmation
            if not self.confirm_session_key(client_socket, drone_info):
                print(f"[MCC] Session key confirmation failed for {drone_id}")
                return
            
            # Register drone
            with self.drones_lock:
                self.drones[drone_id] = drone_info
            
            print(f"[MCC] ✓ Drone {drone_id} authenticated successfully!")
            
            # Send success
            status_msg = StatusMessage(OpCode.SUCCESS, "Authentication complete")
            send_message(client_socket, status_msg)
            
            # Keep connection alive
            self.maintain_connection(drone_id, client_socket)
        
        except Exception as e:
            print(f"[MCC] Error handling drone {drone_id or address}: {e}")
        
        finally:
            # Cleanup
            if drone_id:
                with self.drones_lock:
                    if drone_id in self.drones:
                        del self.drones[drone_id]
                print(f"[MCC] Drone {drone_id} disconnected")
            client_socket.close()
    
    def send_parameters(self, client_socket: socket.socket) -> bool:
        """Phase 0: Send initialization parameters to drone"""
        try:
            msg = ParameterInitMessage(
                p=self.p,
                g=self.g,
                sl=self.security_level,
                ts=utils.current_timestamp(),
                id_mcc=config.MCC_ID,
                y_mcc=self.keypair.y  # Send MCC's public key
            )
            send_message(client_socket, msg)
            return True
        except Exception as e:
            print(f"[MCC] Error sending parameters: {e}")
            return False
    
    def authenticate_drone(self, client_socket: socket.socket, address) -> Tuple[Optional[str], Optional[DroneInfo]]:
        """Phase 1: Authenticate drone"""
        try:
            # Receive authentication request
            msg_data = receive_message(client_socket)
            if not msg_data or get_opcode(msg_data) != OpCode.AUTH_REQ:
                print(f"[MCC] Invalid authentication request from {address}")
                return None, None
            
            auth_req = AuthRequestMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
            
            print(f"[MCC] Authentication request from {auth_req.id_drone}")
            
            # Validate timestamp
            if not utils.validate_timestamp(auth_req.ts):
                print(f"[MCC] Invalid timestamp from {auth_req.id_drone}")
                return None, None
            
            # Check if drone sent its public key
            if not auth_req.y_drone:
                print(f"[MCC] Drone public key not received")
                return None, None
            
            # Store drone's public key
            drone_public_key = (self.p, self.g, auth_req.y_drone)
            
            # Verify drone's signature
            signed_data = (
                str(auth_req.ts) + 
                auth_req.rn.hex() + 
                auth_req.id_drone +
                str(auth_req.ciphertext[0]) + 
                str(auth_req.ciphertext[1])
            ).encode('utf-8')
            msg_hash = crypto_utils.hash_message(signed_data)
            
            if not ElGamal.verify(msg_hash, auth_req.signature, drone_public_key):
                print(f"[MCC] Signature verification failed for {auth_req.id_drone}")
                return None, None
            
            print(f"[MCC] ✓ Drone signature verified")
            
            # Decrypt ciphertext to get K_Di,MCC
            try:
                k_di_mcc_int = ElGamal.decrypt(auth_req.ciphertext, self.keypair)
                k_di_mcc = crypto_utils.int_to_bytes(k_di_mcc_int, 32)
            except Exception as e:
                print(f"[MCC] Failed to decrypt drone secret: {e}")
                return None, None
            
            print(f"[MCC] ✓ Decrypted shared secret from {auth_req.id_drone}")
            
            # Generate MCC nonce
            rn_mcc = utils.generate_random_bytes(32)
            ts_mcc = utils.current_timestamp()
            
            # Encrypt K_Di,MCC with drone's public key
            k_di_mcc_int_back = crypto_utils.bytes_to_int(k_di_mcc)
            c_mcc = ElGamal.encrypt(k_di_mcc_int_back, drone_public_key)
            
            # Sign response
            signed_data_mcc = (
                str(ts_mcc) +
                rn_mcc.hex() +
                config.MCC_ID +
                str(c_mcc[0]) +
                str(c_mcc[1])
            ).encode('utf-8')
            msg_hash_mcc = crypto_utils.hash_message(signed_data_mcc)
            signature_mcc = ElGamal.sign(msg_hash_mcc, self.keypair)
            
            # Send authentication response
            auth_res = AuthResponseMessage(
                ts=ts_mcc,
                rn=rn_mcc,
                id_mcc=config.MCC_ID,
                ciphertext=c_mcc,
                signature=signature_mcc
            )
            send_message(client_socket, auth_res)
            
            print(f"[MCC] ✓ Sent authentication response to {auth_req.id_drone}")
            
            # Derive session key
            session_key = utils.derive_session_key(
                k_di_mcc,
                auth_req.ts,
                ts_mcc,
                auth_req.rn,
                rn_mcc
            )
            
            print(f"[MCC] ✓ Derived session key for {auth_req.id_drone}")
            
            # Create drone info
            drone_info = DroneInfo(
                drone_id=auth_req.id_drone,
                socket=client_socket,
                session_key=session_key,
                public_key=drone_public_key,  # Store drone's public key
                timestamp_i=auth_req.ts,
                nonce_i=auth_req.rn,
                authenticated=False
            )
            
            return auth_req.id_drone, drone_info
        
        except Exception as e:
            print(f"[MCC] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return None, None
    
    def confirm_session_key(self, client_socket: socket.socket, drone_info: DroneInfo) -> bool:
        """Phase 2: Confirm session key with drone"""
        try:
            # Receive session key confirmation
            msg_data = receive_message(client_socket)
            if not msg_data or get_opcode(msg_data) != OpCode.SK_CONFIRM:
                print(f"[MCC] Invalid session key confirmation")
                return False
            
            sk_confirm = SessionKeyConfirmMessage.from_bytes(
                json.dumps(msg_data).encode('utf-8')
            )
            
            # Verify HMAC
            data_to_verify = (sk_confirm.id_drone + str(sk_confirm.ts)).encode('utf-8')
            
            if not utils.verify_hmac(drone_info.session_key, data_to_verify, sk_confirm.hmac_tag):
                print(f"[MCC] HMAC verification failed for {drone_info.drone_id}")
                status_msg = StatusMessage(OpCode.ERR_MISMATCH, "HMAC verification failed")
                send_message(client_socket, status_msg)
                return False
            
            drone_info.authenticated = True
            print(f"[MCC] ✓ Session key confirmed for {drone_info.drone_id}")
            return True
        
        except Exception as e:
            print(f"[MCC] Session key confirmation error: {e}")
            return False
    
    def maintain_connection(self, drone_id: str, client_socket: socket.socket):
        """Keep connection alive and handle incoming messages"""
        try:
            client_socket.settimeout(1.0)
            while self.running:
                try:
                    msg_data = receive_message(client_socket)
                    if msg_data:
                        opcode = get_opcode(msg_data)
                        # Handle ACK or other drone responses
                        if opcode == OpCode.ACK:
                            ack_msg = AckMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
                            print(f"[MCC] ← ACK from {drone_id}: {ack_msg.message}")
                        else:
                            print(f"[MCC] ← Message from {drone_id}: opcode={opcode}")
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[MCC] Connection lost with {drone_id}: {e}")
                    break
        except Exception as e:
            print(f"[MCC] Connection error with {drone_id}: {e}")
    
    def list_drones(self):
        """List all authenticated drones"""
        with self.drones_lock:
            if not self.drones:
                print("[MCC] No drones connected")
                return
            
            print(f"\n[MCC] Connected Drones ({len(self.drones)}):")
            print("-" * 60)
            for drone_id, info in self.drones.items():
                status = "✓ Authenticated" if info.authenticated else "⧗ Pending"
                print(f"  {drone_id}: {status}")
            print("-" * 60 + "\n")
    
    def broadcast_command(self, command: str):
        """Broadcast command to all drones using group key"""
        try:
            # First, check if we have drones and make a snapshot
            with self.drones_lock:
                if not self.drones:
                    print("[MCC] No drones connected to broadcast to")
                    return
                
                # Create a snapshot of drones to avoid holding lock during I/O
                drones_snapshot = list(self.drones.items())
            
            print(f"\n[MCC] Broadcasting command: '{command}'")
            
            # Generate/regenerate group key (needs lock briefly)
            self.generate_group_key()
            
            # Send group key to all drones (no lock needed - using snapshot)
            print("[MCC] Distributing group key...")
            for drone_id, drone_info in drones_snapshot:
                try:
                    self.send_group_key(drone_info)
                    print(f"[MCC]   ✓ Sent to {drone_id}")
                except Exception as e:
                    print(f"[MCC]   ✗ Failed to send to {drone_id}: {e}")
            
            # Encrypt and broadcast command
            print("[MCC] Sending encrypted command...")
            encrypted_cmd = utils.aes_encrypt(self.group_key, command.encode('utf-8'))
            hmac_tag = utils.compute_hmac(self.group_key, encrypted_cmd)
            
            cmd_msg = GroupCommandMessage(encrypted_cmd, hmac_tag)
            
            for drone_id, drone_info in drones_snapshot:
                try:
                    send_message(drone_info.socket, cmd_msg)
                    print(f"[MCC]   ✓ Broadcast to {drone_id}")
                except Exception as e:
                    print(f"[MCC]   ✗ Failed to broadcast to {drone_id}: {e}")
            
            print(f"[MCC] ✓ Broadcast complete!\n")
        
        except Exception as e:
            print(f"[MCC] Error during broadcast: {e}")
            import traceback
            traceback.print_exc()
    
    def generate_group_key(self):
        """Generate group key from all session keys"""
        with self.drones_lock:
            if not self.drones:
                return
            
            # GK = H(SK1 || SK2 || ... || SKn || KR_MCC)
            data = b''
            for drone_info in self.drones.values():
                data += drone_info.session_key
            
            # Add MCC's private key contribution (auto-calculate byte length for large numbers)
            kr_mcc = crypto_utils.int_to_bytes(self.keypair.x)
            data += kr_mcc
            
            self.group_key = hashlib.sha256(data).digest()
            print(f"[MCC] ✓ Group key generated from {len(self.drones)} session keys")
    
    def send_group_key(self, drone_info: DroneInfo):
        """Send group key to specific drone"""
        if not self.group_key:
            raise ValueError("Group key not generated")
        
        # Encrypt group key with drone's session key
        encrypted_gk = utils.aes_encrypt(drone_info.session_key, self.group_key)
        hmac_tag = utils.compute_hmac(drone_info.session_key, encrypted_gk)
        
        gk_msg = GroupKeyMessage(encrypted_gk, hmac_tag)
        send_message(drone_info.socket, gk_msg)
    
    def shutdown(self):
        """Shutdown server"""
        print("\n[MCC] Shutting down server...")
        
        # Send shutdown to all drones
        with self.drones_lock:
            for drone_id, drone_info in list(self.drones.items()):
                try:
                    shutdown_msg = ShutdownMessage()
                    send_message(drone_info.socket, shutdown_msg)
                    drone_info.socket.close()
                except:
                    pass
            self.drones.clear()
        
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        print("[MCC] Server shutdown complete")
    
    def run_cli(self):
        """Run command-line interface"""
        print("\n" + "="*60)
        print("MCC Command Interface")
        print("="*60)
        print("Commands:")
        print("  list          - Show all authenticated drones")
        print("  broadcast <cmd> - Send command to all drones")
        print("  shutdown      - Close all sessions and exit")
        print("="*60 + "\n")
        
        while self.running:
            try:
                cmd = input("MCC> ").strip()
                
                if not cmd:
                    continue
                
                if cmd == "list":
                    self.list_drones()
                
                elif cmd.startswith("broadcast "):
                    command = cmd[10:].strip()
                    if command:
                        self.broadcast_command(command)
                    else:
                        print("[MCC] Usage: broadcast <command>")
                
                elif cmd == "shutdown":
                    self.shutdown()
                    break
                
                else:
                    print(f"[MCC] Unknown command: {cmd}")
            
            except KeyboardInterrupt:
                print("\n[MCC] Interrupted")
                self.shutdown()
                break
            except Exception as e:
                print(f"[MCC] Error: {e}")


def main():
    """Main entry point"""
    print("""
╔════════════════════════════════════════════════════════════╗
║   UAV Command and Control System - Mission Control Center  ║
║   Secure Communication with ElGamal & Digital Signatures   ║
╚════════════════════════════════════════════════════════════╝
""")
    
    mcc = MCCServer()
    
    try:
        mcc.start()
        mcc.run_cli()
    except KeyboardInterrupt:
        print("\n[MCC] Interrupted by user")
        mcc.shutdown()
    except Exception as e:
        print(f"[MCC] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        mcc.shutdown()


if __name__ == "__main__":
    main()
