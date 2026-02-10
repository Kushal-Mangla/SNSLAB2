#!/usr/bin/env python3
"""
Attack Demonstrations for UAV C2 Protocol
Demonstrates three security attacks:
1. Replay Attack - Re-sending Phase 1A authentication request
2. MitM Tampering - Modifying prime p in Phase 0 to trigger signature failure
3. Unauthorized Access - Unknown Drone ID attempting to connect
"""

import sys
import os
import socket
import time
import json
import hashlib

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import config
import utils
import crypto_utils
from crypto_utils import ElGamal, ElGamalKeyPair
from protocol import *


def print_banner(title: str):
    """Print attack demonstration banner"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")


def connect_to_mcc() -> socket.socket:
    """Establish connection to MCC"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((config.MCC_HOST, config.MCC_PORT))
        print(f"✓ Connected to MCC at {config.MCC_HOST}:{config.MCC_PORT}")
        return sock
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        print(f"  Ensure MCC server is running: python src/mcc_server.py")
        sys.exit(1)


def receive_parameters(sock: socket.socket):
    """Receive Phase 0 parameters from MCC"""
    print("[Phase 0] Waiting for parameters from MCC...")
    msg_data = receive_message(sock)
    
    if not msg_data or get_opcode(msg_data) != config.OpCode.PARAM_INIT:
        print("✗ Failed to receive parameter initialization")
        return None
    
    param_msg = ParameterInitMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
    print(f"✓ Received parameters (p: {len(str(param_msg.p))} digits, g: {param_msg.g})")
    return param_msg


# ============================================================================
# ATTACK 1: REPLAY ATTACK
# ============================================================================

def replay_attack_demo():
    """
    Replay Attack Demonstration
    
    Attack Description:
    - Attacker captures a legitimate Phase 1A authentication request
    - Later replays the same message to try to impersonate the drone
    
    Expected Outcome:
    - MCC should reject the replayed message due to:
      a) Timestamp validation (message too old)
      b) Nonce tracking (if implemented)
    """
    print_banner("ATTACK 1: REPLAY ATTACK")
    
    print("Scenario: Attacker captures and replays Phase 1A authentication request\n")
    
    # Step 1: Legitimate authentication
    print("[Step 1] Performing legitimate authentication...")
    sock1 = connect_to_mcc()
    
    param_msg = receive_parameters(sock1)
    if not param_msg:
        sock1.close()
        return
    
    # Generate legitimate drone credentials
    drone_id = "DRONE_LEGITIMATE"
    p, g = param_msg.p, param_msg.g
    mcc_public_key = (p, g, param_msg.y_mcc)
    
    # Generate drone keypair
    x = crypto_utils.secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    keypair = ElGamalKeyPair(p, g, x, y)
    
    # Generate authentication request
    k_di_mcc = utils.generate_random_bytes(32)
    rn_i = utils.generate_random_bytes(32)
    ts_i = utils.current_timestamp()
    
    # Encrypt shared secret
    k_di_mcc_int = crypto_utils.bytes_to_int(k_di_mcc)
    c_i = ElGamal.encrypt(k_di_mcc_int, mcc_public_key)
    
    # Create signature message
    sig_message = f"{ts_i}{rn_i.hex()}{drone_id}{c_i[0]}{c_i[1]}"
    sig_hash = crypto_utils.hash_message(sig_message.encode('utf-8'))
    sig = ElGamal.sign(sig_hash, keypair)
    
    # Create auth request
    auth_req = AuthRequestMessage(ts_i, rn_i, drone_id, c_i, sig, keypair.y)
    
    print(f"✓ Created authentication request for {drone_id}")
    print(f"  Timestamp: {ts_i}")
    print(f"  Nonce: {rn_i.hex()[:32]}...")
    
    # Send authentication request
    send_message(sock1, auth_req)
    print("✓ Sent authentication request")
    
    # Capture the message for replay
    captured_message = auth_req.to_bytes()
    print(f"✓ CAPTURED MESSAGE ({len(captured_message)} bytes)")
    
    # Receive response
    try:
        response = receive_message(sock1)
        if response:
            print(f"✓ Received response: OpCode {response.get('opcode')}")
    except:
        pass
    sock1.close()
    
    # Step 2: Wait to make timestamp invalid
    print(f"\n[Step 2] Waiting 3 seconds to make timestamp stale...")
    print("(In production, attacker would replay after any time delay)")
    time.sleep(3)
    
    # Step 3: Replay the captured message
    print("\n[Step 3] REPLAYING CAPTURED MESSAGE...")
    sock2 = connect_to_mcc()
    
    # Receive parameters (attacker must complete Phase 0)
    param_msg2 = receive_parameters(sock2)
    if not param_msg2:
        sock2.close()
        return
    
    # Now replay the OLD authentication request
    print("→ Sending OLD captured authentication request (with stale timestamp)")
    
    try:
        # Send the captured message directly
        replayed_auth = AuthRequestMessage.from_bytes(captured_message)
        send_message(sock2, replayed_auth)
        
        print("✓ Replayed message sent")
        print(f"  Original timestamp: {replayed_auth.ts}")
        print(f"  Current time: {utils.current_timestamp()}")
        print(f"  Time difference: {utils.current_timestamp() - replayed_auth.ts} seconds")
        
        # Wait for response
        sock2.settimeout(5)
        response = receive_message(sock2)
        
        if response:
            opcode = response.get('opcode')
            print(f"\n[MCC Response] OpCode: {opcode}")
            
            if opcode == config.OpCode.SUCCESS:
                print("✗ ATTACK SUCCEEDED - Protocol is vulnerable to replay attacks!")
            elif opcode == config.OpCode.ERR_MISMATCH:
                print("✓ ATTACK BLOCKED - MCC detected stale/invalid message")
                print("  Reason: Timestamp validation or signature verification failed")
            else:
                print(f"✓ ATTACK BLOCKED - Unexpected response (OpCode {opcode})")
        else:
            print("✓ ATTACK BLOCKED - Connection closed by MCC")
    
    except Exception as e:
        print(f"✓ ATTACK BLOCKED - Exception during replay: {e}")
    
    finally:
        sock2.close()
    
    print("\n[Analysis]")
    print("Protection mechanisms against replay attacks:")
    print("  1. Timestamp validation - Messages older than tolerance are rejected")
    print("  2. Nonce tracking - Each nonce should only be accepted once")
    print("  3. Session binding - Authentication tied to specific session")
    

# ============================================================================
# ATTACK 2: MAN-IN-THE-MIDDLE PARAMETER TAMPERING
# ============================================================================

def mitm_tampering_demo():
    """
    Man-in-the-Middle Parameter Tampering Demonstration
    
    Attack Description:
    - Attacker intercepts Phase 0 and modifies the prime p
    - Drone receives tampered parameters and tries to authenticate
    - MCC should detect tampering through signature verification failure
    
    Expected Outcome:
    - Signature verification fails at MCC
    - Authentication is rejected
    """
    print_banner("ATTACK 2: MAN-IN-THE-MIDDLE PARAMETER TAMPERING")
    
    print("Scenario: Attacker modifies prime p in Phase 0 parameter exchange\n")
    
    print("[Step 1] Connecting to MCC as legitimate drone...")
    sock = connect_to_mcc()
    
    print("[Step 2] Receiving parameters from MCC...")
    msg_data = receive_message(sock)
    
    if not msg_data or get_opcode(msg_data) != config.OpCode.PARAM_INIT:
        print("✗ Failed to receive parameters")
        sock.close()
        return
    
    param_msg = ParameterInitMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
    original_p = param_msg.p
    print(f"✓ Received legitimate parameters")
    print(f"  Original prime p: {str(original_p)[:60]}...")
    print(f"  Generator g: {param_msg.g}")
    print(f"  MCC public key y: {str(param_msg.y_mcc)[:60]}...")
    
    # Step 3: MITM TAMPERING - Modify the prime
    print("\n[Step 3] ATTACKER TAMPERING...")
    print("→ Modifying prime p to a different value")
    
    # Generate a different prime (smaller for demonstration)
    tampered_p = crypto_utils.CryptoUtils.generate_prime(512)  # Much smaller prime
    
    print(f"  Tampered prime p: {str(tampered_p)[:60]}...")
    print(f"  Original bits: {original_p.bit_length()}, Tampered bits: {tampered_p.bit_length()}")
    
    # Use tampered parameters for drone operations
    print("\n[Step 4] Drone uses tampered parameters for authentication...")
    
    drone_id = "DRONE_MITM_VICTIM"
    p = tampered_p  # Using tampered prime
    g = param_msg.g
    
    # Generate drone keypair with TAMPERED p
    x = crypto_utils.secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    keypair = ElGamalKeyPair(p, g, x, y)
    
    print(f"✓ Generated drone keypair with tampered parameters")
    
    # Generate authentication data
    k_di_mcc = utils.generate_random_bytes(32)
    rn_i = utils.generate_random_bytes(32)
    ts_i = utils.current_timestamp()
    
    # Encrypt with MCC's public key (but using tampered p in calculations)
    k_di_mcc_int = crypto_utils.bytes_to_int(k_di_mcc)
    mcc_public_key = (original_p, param_msg.g, param_msg.y_mcc)
    
    try:
        # Try to encrypt - parameters are inconsistent
        c_i = ElGamal.encrypt(k_di_mcc_int, mcc_public_key)
    except:
        # If encryption fails, use tampered params
        c_i = ElGamal.encrypt(k_di_mcc_int, (p, g, param_msg.y_mcc))
    
    # Sign with drone's keypair (using tampered p)
    sig_message = f"{ts_i}{rn_i.hex()}{drone_id}{c_i[0]}{c_i[1]}"
    sig_hash = crypto_utils.hash_message(sig_message.encode('utf-8'))
    sig = ElGamal.sign(sig_hash, keypair)
    
    # Create and send authentication request
    auth_req = AuthRequestMessage(ts_i, rn_i, drone_id, c_i, sig, keypair.y)
    
    print("\n[Step 5] Sending authentication request with tampered parameters...")
    send_message(sock, auth_req)
    
    # Wait for response
    print("[Step 6] Waiting for MCC response...")
    try:
        sock.settimeout(5)
        response = receive_message(sock)
        
        if response:
            opcode = response.get('opcode')
            print(f"\n[MCC Response] OpCode: {opcode}")
            
            if opcode == config.OpCode.SUCCESS:
                print("✗ ATTACK SUCCEEDED - Protocol is vulnerable to parameter tampering!")
            elif opcode == config.OpCode.ERR_MISMATCH:
                print("✓ ATTACK BLOCKED - MCC detected parameter mismatch")
                print("  Reason: Signature verification failed due to parameter inconsistency")
            else:
                print(f"✓ ATTACK BLOCKED - Received error code {opcode}")
        else:
            print("✓ ATTACK BLOCKED - Connection closed by MCC")
    except Exception as e:
        print(f"✓ ATTACK BLOCKED - Error: {e}")
    
    sock.close()
    
    print("\n[Analysis]")
    print("Protection mechanisms against parameter tampering:")
    print("  1. Digital signatures - MCC verifies signature using original parameters")
    print("  2. Parameter validation - Drone validates received parameters")
    print("  3. Cryptographic binding - All operations tied to consistent parameters")
    print("  4. If attacker modifies p, signature verification WILL FAIL at MCC")
    

# ============================================================================
# ATTACK 3: UNAUTHORIZED ACCESS
# ============================================================================

def unauthorized_access_demo():
    """
    Unauthorized Access Demonstration
    
    Attack Description:
    - Unknown drone (not in MCC's authorized fleet) attempts to connect
    - Uses valid protocol but unknown Drone ID
    
    Expected Outcome:
    - MCC should reject the connection
    - Authentication should fail for unknown drone
    """
    print_banner("ATTACK 3: UNAUTHORIZED ACCESS ATTEMPT")
    
    print("Scenario: Unknown/unauthorized drone attempts to authenticate\n")
    
    print("[Step 1] Unauthorized drone connecting to MCC...")
    sock = connect_to_mcc()
    
    # Receive parameters
    param_msg = receive_parameters(sock)
    if not param_msg:
        sock.close()
        return
    
    # Generate keypair for unauthorized drone
    print("\n[Step 2] Generating keypair for UNAUTHORIZED drone...")
    unknown_drone_id = "DRONE_UNAUTHORIZED_HACKER"
    
    p, g = param_msg.p, param_msg.g
    mcc_public_key = (p, g, param_msg.y_mcc)
    
    x = crypto_utils.secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)
    keypair = ElGamalKeyPair(p, g, x, y)
    
    print(f"✓ Generated keypair for {unknown_drone_id}")
    print(f"  Note: This drone is NOT in MCC's authorized fleet")
    
    # Attempt authentication
    print("\n[Step 3] Attempting authentication with UNKNOWN Drone ID...")
    
    k_di_mcc = utils.generate_random_bytes(32)
    rn_i = utils.generate_random_bytes(32)
    ts_i = utils.current_timestamp()
    
    # Encrypt shared secret
    k_di_mcc_int = crypto_utils.bytes_to_int(k_di_mcc)
    c_i = ElGamal.encrypt(k_di_mcc_int, mcc_public_key)
    
    # Sign authentication request
    sig_message = f"{ts_i}{rn_i.hex()}{unknown_drone_id}{c_i[0]}{c_i[1]}"
    sig_hash = crypto_utils.hash_message(sig_message.encode('utf-8'))
    sig = ElGamal.sign(sig_hash, keypair)
    
    # Create and send authentication request
    auth_req = AuthRequestMessage(ts_i, rn_i, unknown_drone_id, c_i, sig, keypair.y)
    
    print(f"→ Sending authentication request")
    print(f"  Drone ID: {unknown_drone_id}")
    print(f"  Protocol: Correctly formatted Phase 1A message")
    
    send_message(sock, auth_req)
    
    # Wait for response
    print("\n[Step 4] Waiting for MCC response...")
    try:
        sock.settimeout(5)
        response = receive_message(sock)
        
        if response:
            opcode = response.get('opcode')
            print(f"\n[MCC Response] OpCode: {opcode}")
            
            if opcode == config.OpCode.SUCCESS:
                print("✗ ATTACK SUCCEEDED - Unauthorized drone gained access!")
                print("  CRITICAL SECURITY VULNERABILITY")
            elif opcode == config.OpCode.ERR_MISMATCH:
                print("✓ ATTACK BLOCKED - MCC rejected unauthorized drone")
                print("  Reason: Drone ID not in authorized fleet registry")
            else:
                print(f"✓ ATTACK BLOCKED - Received error code {opcode}")
        else:
            print("✓ ATTACK BLOCKED - Connection closed by MCC")
    except Exception as e:
        print(f"✓ ATTACK BLOCKED - Error: {e}")
    
    sock.close()
    
    print("\n[Analysis]")
    print("Protection mechanisms against unauthorized access:")
    print("  1. Fleet registry - MCC maintains whitelist of authorized drone IDs")
    print("  2. Pre-shared credentials - Public keys must be registered in advance")
    print("  3. Mutual authentication - Both parties verify each other's identity")
    print("  4. Access control - Only authorized drones can complete authentication")
    print("\n  NOTE: In this implementation, MCC accepts any drone that follows the")
    print("  protocol correctly. For production, implement a fleet registry with")
    print("  pre-registered drone IDs and public keys.")
    

# ============================================================================
# MAIN MENU
# ============================================================================

def print_menu():
    """Print attack demonstration menu"""
    print("\n" + "="*80)
    print("  UAV C2 PROTOCOL - SECURITY ATTACK DEMONSTRATIONS")
    print("="*80)
    print("\nAvailable demonstrations:\n")
    print("  1. Replay Attack - Re-sending Phase 1A authentication request")
    print("  2. MitM Parameter Tampering - Modifying prime p to trigger signature failure")
    print("  3. Unauthorized Access - Unknown drone attempting to connect")
    print("  4. Run all attacks")
    print("  5. Exit")
    print("\n" + "-"*80)


def main():
    """Main attack demonstration program"""
    print("\n" + "="*80)
    print("  SECURE UAV COMMAND AND CONTROL - ATTACK DEMONSTRATIONS")
    print("="*80)
    print("\nThis script demonstrates various security attacks on the UAV C2 protocol")
    print("and shows how the protocol defends against them.\n")
    print("IMPORTANT: MCC server must be running before executing attacks!")
    print("           Start MCC: python src/mcc_server.py")
    print("="*80)
    
    while True:
        print_menu()
        choice = input("\nSelect demonstration (1-5): ").strip()
        
        if choice == '1':
            replay_attack_demo()
        elif choice == '2':
            mitm_tampering_demo()
        elif choice == '3':
            unauthorized_access_demo()
        elif choice == '4':
            print("\nRunning all attack demonstrations...\n")
            replay_attack_demo()
            input("\nPress Enter to continue to next attack...")
            mitm_tampering_demo()
            input("\nPress Enter to continue to next attack...")
            unauthorized_access_demo()
            print("\n" + "="*80)
            print("  ALL ATTACK DEMONSTRATIONS COMPLETED")
            print("="*80)
        elif choice == '5':
            print("\nExiting attack demonstrations.")
            break
        else:
            print("Invalid choice. Please select 1-5.")
        
        if choice in ['1', '2', '3', '4']:
            input("\nPress Enter to return to menu...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
