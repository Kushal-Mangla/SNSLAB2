#!/usr/bin/env python3
"""
Drone Client
Connects to MCC, performs mutual authentication, receives commands
"""

import socket
import threading
import time
import hashlib
import json
from typing import Optional, Tuple

import config
import utils
import crypto_utils
from crypto_utils import ElGamal, ElGamalKeyPair
from protocol import *


class DroneClient:
    """Drone client for UAV C2 system"""
    
    def __init__(self, drone_id: str):
        self.drone_id = drone_id
        self.socket: Optional[socket.socket] = None
        
        # Received MCC parameters
        self.p: Optional[int] = None
        self.g: Optional[int] = None
        self.security_level: Optional[int] = None
        self.mcc_public_key: Optional[Tuple[int, int, int]] = None
        
        # Own keypair
        self.keypair: Optional[ElGamalKeyPair] = None
        
        # Shared secret and session key
        self.k_di_mcc: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.group_key: Optional[bytes] = None
        
        # Protocol state
        self.authenticated = False
        self.running = False
        
        print(f"[{self.drone_id}] Drone initialized")
    
    def connect(self, host: str = config.MCC_HOST, port: int = config.MCC_PORT) -> bool:
        """Connect to MCC server"""
        try:
            print(f"[{self.drone_id}] Connecting to MCC at {host}:{port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            print(f"[{self.drone_id}] ✓ Connected to MCC")
            return True
        except Exception as e:
            print(f"[{self.drone_id}] Connection failed: {e}")
            return False
    
    def receive_parameters(self) -> bool:
        """Phase 0: Receive and validate parameters from MCC"""
        try:
            print(f"[{self.drone_id}] Waiting for parameters...")
            msg_data = receive_message(self.socket)
            
            if not msg_data or get_opcode(msg_data) != OpCode.PARAM_INIT:
                print(f"[{self.drone_id}] Invalid parameter message")
                return False
            
            param_msg = ParameterInitMessage.from_bytes(
                json.dumps(msg_data).encode('utf-8')
            )
            
            print(f"[{self.drone_id}] Received parameters from {param_msg.id_mcc}")
            print(f"[{self.drone_id}]   Security Level: {param_msg.sl} bits")
            print(f"[{self.drone_id}]   Prime p: {str(param_msg.p)[:50]}... ({len(str(param_msg.p))} digits)")
            print(f"[{self.drone_id}]   Generator g: {param_msg.g}")
            
            # Validate security level
            if param_msg.sl < config.DRONE_MIN_SECURITY_LEVEL:
                print(f"[{self.drone_id}] ✗ Security level too low!")
                print(f"[{self.drone_id}] Required: {config.DRONE_MIN_SECURITY_LEVEL}, Got: {param_msg.sl}")
                return False
            
            # Validate prime bit length
            actual_bits = param_msg.p.bit_length()
            if abs(actual_bits - param_msg.sl) > 10:  # Allow small tolerance
                print(f"[{self.drone_id}] ✗ Prime bit length mismatch!")
                print(f"[{self.drone_id}] Expected: ~{param_msg.sl}, Got: {actual_bits}")
                return False
            
            # Validate timestamp
            if not utils.validate_timestamp(param_msg.ts):
                print(f"[{self.drone_id}] ✗ Invalid timestamp")
                return False
            
            # Store parameters
            self.p = param_msg.p
            self.g = param_msg.g
            self.security_level = param_msg.sl
            self.mcc_public_key = (param_msg.p, param_msg.g, param_msg.y_mcc) if param_msg.y_mcc else None
            
            if not self.mcc_public_key:
                print(f"[{self.drone_id}] ✗ MCC public key not received")
                return False
            
            print(f"[{self.drone_id}] ✓ Parameters validated")
            return True
        
        except Exception as e:
            print(f"[{self.drone_id}] Error receiving parameters: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def generate_keypair(self):
        """Generate drone's own ElGamal keypair"""
        print(f"[{self.drone_id}] Generating ElGamal keypair...")
        
        # Use received p and g
        # Generate private key
        x = crypto_utils.secrets.randbelow(self.p - 2) + 1
        y = pow(self.g, x, self.p)
        
        self.keypair = ElGamalKeyPair(self.p, self.g, x, y)
        print(f"[{self.drone_id}] ✓ Keypair generated")
    
    def authenticate(self) -> bool:
        """Phase 1: Perform mutual authentication with MCC"""
        try:
            # Generate shared secret
            self.k_di_mcc = utils.generate_random_bytes(32)
            print(f"[{self.drone_id}] Generated shared secret K_Di,MCC")
            
            # Generate nonce
            rn_i = utils.generate_random_bytes(32)
            ts_i = utils.current_timestamp()
            
            # For MCC public key, we need to receive it or have it pre-shared
            # For this implementation, we'll construct it from received parameters
            # In Phase 0, we should also receive MCC's public key y
            # For now, we'll use a workaround: encrypt with parameters and let MCC decrypt
            
            # Convert shared secret to integer for encryption
            k_di_mcc_int = crypto_utils.bytes_to_int(self.k_di_mcc)
            
            # Encrypt with MCC's public key
            c_i = ElGamal.encrypt(k_di_mcc_int, self.mcc_public_key)
            
            # Sign the authentication request
            signed_data = (
                str(ts_i) +
                rn_i.hex() +
                self.drone_id +
                str(c_i[0]) +
                str(c_i[1])
            ).encode('utf-8')
            msg_hash = crypto_utils.hash_message(signed_data)
            signature_i = ElGamal.sign(msg_hash, self.keypair)
            
            # Send authentication request with drone's public key
            auth_req = AuthRequestMessage(
                ts=ts_i,
                rn=rn_i,
                id_drone=self.drone_id,
                ciphertext=c_i,
                signature=signature_i,
                y_drone=self.keypair.y  # Send drone's public key
            )
            send_message(self.socket, auth_req)
            print(f"[{self.drone_id}] ✓ Sent authentication request")
            
            # Receive authentication response
            print(f"[{self.drone_id}] Waiting for authentication response...")
            msg_data = receive_message(self.socket)
            
            if not msg_data or get_opcode(msg_data) != OpCode.AUTH_RES:
                print(f"[{self.drone_id}] Invalid authentication response")
                return False
            
            auth_res = AuthResponseMessage.from_bytes(
                json.dumps(msg_data).encode('utf-8')
            )
            
            print(f"[{self.drone_id}] ✓ Received authentication response from {auth_res.id_mcc}")
            
            # Validate timestamp
            if not utils.validate_timestamp(auth_res.ts):
                print(f"[{self.drone_id}] ✗ Invalid timestamp in response")
                return False
            
            # Verify signature using MCC's public key
            signed_data_mcc = (
                str(auth_res.ts) +
                auth_res.rn.hex() +
                auth_res.id_mcc +
                str(auth_res.ciphertext[0]) +
                str(auth_res.ciphertext[1])
            ).encode('utf-8')
            msg_hash_mcc = crypto_utils.hash_message(signed_data_mcc)
            
            # Verify MCC's signature
            if not ElGamal.verify(msg_hash_mcc, auth_res.signature, self.mcc_public_key):
                print(f"[{self.drone_id}] ✗ MCC signature verification failed")
                return False
            
            print(f"[{self.drone_id}] ✓ MCC signature verified")
            
            # Decrypt response (should contain our K_Di,MCC echoed back)
            try:
                k_di_mcc_back_int = ElGamal.decrypt(auth_res.ciphertext, self.keypair)
                k_di_mcc_back = crypto_utils.int_to_bytes(k_di_mcc_back_int, 32)
                
                # Verify it matches our original shared secret
                if k_di_mcc_back != self.k_di_mcc:
                    print(f"[{self.drone_id}] ✗ Shared secret mismatch")
                    return False
                
                print(f"[{self.drone_id}] ✓ Decrypted and verified shared secret")
            except Exception as e:
                print(f"[{self.drone_id}] Failed to decrypt MCC response: {e}")
                return False
            
            # Derive session key
            self.session_key = utils.derive_session_key(
                self.k_di_mcc,
                ts_i,
                auth_res.ts,
                rn_i,
                auth_res.rn
            )
            
            print(f"[{self.drone_id}] ✓ Derived session key")
            
            # Store authentication parameters for confirmation
            self.ts_i = ts_i
            self.ts_mcc = auth_res.ts
            self.rn_i = rn_i
            self.rn_mcc = auth_res.rn
            
            return True
        
        except Exception as e:
            print(f"[{self.drone_id}] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def confirm_session_key(self) -> bool:
        """Phase 2: Confirm session key establishment"""
        try:
            ts_final = utils.current_timestamp()
            
            # Compute HMAC
            data = (self.drone_id + str(ts_final)).encode('utf-8')
            hmac_tag = utils.compute_hmac(self.session_key, data)
            
            # Send confirmation
            sk_confirm = SessionKeyConfirmMessage(
                id_drone=self.drone_id,
                ts=ts_final,
                hmac_tag=hmac_tag
            )
            send_message(self.socket, sk_confirm)
            print(f"[{self.drone_id}] ✓ Sent session key confirmation")
            
            # Wait for success response
            msg_data = receive_message(self.socket)
            
            if not msg_data:
                print(f"[{self.drone_id}] No response received")
                return False
            
            opcode = get_opcode(msg_data)
            
            if opcode == OpCode.SUCCESS:
                status = StatusMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
                print(f"[{self.drone_id}] ✓ {status.message}")
                self.authenticated = True
                return True
            
            elif opcode == OpCode.ERR_MISMATCH:
                status = StatusMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
                print(f"[{self.drone_id}] ✗ Authentication failed: {status.message}")
                return False
            
            else:
                print(f"[{self.drone_id}] Unexpected response opcode: {opcode}")
                return False
        
        except Exception as e:
            print(f"[{self.drone_id}] Session key confirmation error: {e}")
            return False
    
    def listen_for_commands(self):
        """Listen for commands from MCC"""
        print(f"[{self.drone_id}] Listening for commands...")
        self.running = True
        
        try:
            self.socket.settimeout(1.0)
            
            while self.running:
                try:
                    msg_data = receive_message(self.socket)
                    
                    if not msg_data:
                        continue
                    
                    opcode = get_opcode(msg_data)
                    
                    if opcode == OpCode.GROUP_KEY:
                        self.handle_group_key(msg_data)
                    
                    elif opcode == OpCode.GROUP_CMD:
                        self.handle_group_command(msg_data)
                    
                    elif opcode == OpCode.SHUTDOWN:
                        print(f"[{self.drone_id}] Received shutdown signal")
                        self.running = False
                        break
                    
                    else:
                        print(f"[{self.drone_id}] Unknown opcode: {opcode}")
                
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[{self.drone_id}] Error receiving message: {e}")
                    break
        
        except KeyboardInterrupt:
            print(f"\n[{self.drone_id}] Interrupted by user")
        
        finally:
            self.disconnect()
    
    def handle_group_key(self, msg_data: dict):
        """Handle group key distribution"""
        try:
            gk_msg = GroupKeyMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
            
            # Verify HMAC
            if not utils.verify_hmac(self.session_key, gk_msg.encrypted_gk, gk_msg.hmac_tag):
                print(f"[{self.drone_id}] ✗ Group key HMAC verification failed")
                return
            
            # Decrypt group key
            self.group_key = utils.aes_decrypt(self.session_key, gk_msg.encrypted_gk)
            print(f"[{self.drone_id}] ✓ Received and decrypted group key")
        
        except Exception as e:
            print(f"[{self.drone_id}] Error handling group key: {e}")
    
    def handle_group_command(self, msg_data: dict):
        """Handle group command broadcast"""
        try:
            cmd_msg = GroupCommandMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
            
            if not self.group_key:
                print(f"[{self.drone_id}] ✗ No group key available")
                return
            
            # Verify HMAC
            if not utils.verify_hmac(self.group_key, cmd_msg.encrypted_cmd, cmd_msg.hmac_tag):
                print(f"[{self.drone_id}] ✗ Command HMAC verification failed")
                return
            
            # Decrypt command
            command = utils.aes_decrypt(self.group_key, cmd_msg.encrypted_cmd).decode('utf-8')
            
            print(f"\n[{self.drone_id}] ╔════════════════════════════════════════╗")
            print(f"[{self.drone_id}] ║  RECEIVED COMMAND: {command:20s} ║")
            print(f"[{self.drone_id}] ╚════════════════════════════════════════╝\n")
            
            # Execute command (for demo, just print)
            self.execute_command(command)
        
        except Exception as e:
            print(f"[{self.drone_id}] Error handling command: {e}")
    
    def execute_command(self, command: str):
        """Execute received command"""
        print(f"[{self.drone_id}] Executing: {command}")
        
        # Command execution logic would go here
        # For demo, just acknowledge
        
        if command.lower() == "status":
            print(f"[{self.drone_id}]   → Status: Operational")
            print(f"[{self.drone_id}]   → Battery: 85%")
            print(f"[{self.drone_id}]   → Position: Online")
        
        elif command.lower() == "return":
            print(f"[{self.drone_id}]   → Returning to base...")
        
        elif command.lower().startswith("goto"):
            print(f"[{self.drone_id}]   → Navigating to target...")
        
        else:
            print(f"[{self.drone_id}]   → Command acknowledged")
    
    def disconnect(self):
        """Disconnect from MCC"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print(f"[{self.drone_id}] Disconnected")
    
    def run(self, host: str = config.MCC_HOST, port: int = config.MCC_PORT) -> bool:
        """Main execution flow"""
        # Connect to MCC
        if not self.connect(host, port):
            return False
        
        # Receive and validate parameters
        if not self.receive_parameters():
            self.disconnect()
            return False
        
        # Generate own keypair
        self.generate_keypair()
        
        # Authenticate with MCC
        if not self.authenticate():
            self.disconnect()
            return False
        
        # Confirm session key
        if not self.confirm_session_key():
            self.disconnect()
            return False
        
        print(f"\n[{self.drone_id}] ✓✓✓ Authentication complete! ✓✓✓")
        print(f"[{self.drone_id}] Ready to receive commands\n")
        
        # Listen for commands
        self.listen_for_commands()
        
        return True


def main():
    """Main entry point"""
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════╗
║          UAV Command and Control System - Drone            ║
║   Secure Communication with ElGamal & Digital Signatures   ║
╚════════════════════════════════════════════════════════════╝
""")
    
    # Get drone ID from command line or generate
    if len(sys.argv) > 1:
        drone_id = sys.argv[1]
    else:
        import random
        drone_id = f"DRONE_{random.randint(1000, 9999)}"
    
    # Get host and port if provided
    host = sys.argv[2] if len(sys.argv) > 2 else config.MCC_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else config.MCC_PORT
    
    print(f"Starting drone: {drone_id}")
    print(f"Target MCC: {host}:{port}\n")
    
    drone = DroneClient(drone_id)
    
    try:
        drone.run(host, port)
    except KeyboardInterrupt:
        print(f"\n[{drone_id}] Interrupted by user")
        drone.disconnect()
    except Exception as e:
        print(f"[{drone_id}] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        drone.disconnect()


if __name__ == "__main__":
    main()
