#!/usr/bin/env python3
"""
Integration Tests for UAV C2 System
Tests full authentication flow and system integration
"""

import sys
import time
import socket
import threading
import json
from typing import Optional

import config
import utils
import crypto_utils
from crypto_utils import ElGamal
from protocol import *


class IntegrationTestResults:
    """Track integration test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def record(self, name: str, passed: bool, details: str = ""):
        self.tests.append({'name': name, 'passed': passed, 'details': details})
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        print("\n" + "="*70)
        print("INTEGRATION TEST SUMMARY")
        print("="*70)
        for test in self.tests:
            status = "✓ PASS" if test['passed'] else "✗ FAIL"
            print(f"{status}: {test['name']}")
            if test['details']:
                print(f"       {test['details']}")
        print("="*70)
        print(f"Total: {self.passed + self.failed} | Passed: {self.passed} | Failed: {self.failed}")
        print("="*70)


results = IntegrationTestResults()


class MockMCC:
    """Mock MCC for testing"""
    def __init__(self):
        self.keypair = None
        self.p = None
        self.g = None
        self.server_socket = None
        self.running = False
    
    def start(self, port: int = 9998):
        """Start mock MCC server"""
        # Generate keypair (512-bit for speed)
        print(f"[MockMCC] Generating keypair...")
        self.keypair = ElGamal.generate_keypair(512, skip_check=True)
        self.p = self.keypair.p
        self.g = self.keypair.g
        
        # Start server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("127.0.0.1", port))
        self.server_socket.listen(1)
        self.running = True
        print(f"[MockMCC] Server started on port {port}")
    
    def accept_connection(self):
        """Accept drone connection"""
        self.server_socket.settimeout(10.0)
        client_socket, addr = self.server_socket.accept()
        print(f"[MockMCC] Connection from {addr}")
        return client_socket
    
    def send_parameters(self, client_socket):
        """Send parameters to drone"""
        msg = ParameterInitMessage(
            p=self.p,
            g=self.g,
            sl=512,  # Using 512 for testing
            ts=utils.current_timestamp(),
            id_mcc="TEST_MCC",
            y_mcc=self.keypair.y
        )
        send_message(client_socket, msg)
        print(f"[MockMCC] Sent parameters")
    
    def receive_auth_request(self, client_socket):
        """Receive and process authentication request"""
        msg_data = receive_message(client_socket)
        if not msg_data or get_opcode(msg_data) != config.OpCode.AUTH_REQ:
            return None
        
        auth_req = AuthRequestMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
        print(f"[MockMCC] Received auth request from {auth_req.id_drone}")
        return auth_req
    
    def send_auth_response(self, client_socket, auth_req):
        """Send authentication response"""
        # Decrypt K_Di,MCC
        k_di_mcc_int = ElGamal.decrypt(auth_req.ciphertext, self.keypair)
        k_di_mcc = crypto_utils.int_to_bytes(k_di_mcc_int, 32)
        
        # Prepare response
        rn_mcc = utils.generate_random_bytes(32)
        ts_mcc = utils.current_timestamp()
        
        # Encrypt with drone's public key
        drone_pub_key = (self.p, self.g, auth_req.y_drone)
        c_mcc = ElGamal.encrypt(k_di_mcc_int, drone_pub_key)
        
        # Sign
        signed_data = (
            str(ts_mcc) + rn_mcc.hex() + "TEST_MCC" +
            str(c_mcc[0]) + str(c_mcc[1])
        ).encode('utf-8')
        sig_mcc = ElGamal.sign(crypto_utils.hash_message(signed_data), self.keypair)
        
        # Send
        auth_res = AuthResponseMessage(ts_mcc, rn_mcc, "TEST_MCC", c_mcc, sig_mcc)
        send_message(client_socket, auth_res)
        print(f"[MockMCC] Sent auth response")
        
        return k_di_mcc, auth_req.ts, ts_mcc, auth_req.rn, rn_mcc
    
    def receive_sk_confirm(self, client_socket, session_key):
        """Receive and verify session key confirmation"""
        msg_data = receive_message(client_socket)
        if not msg_data or get_opcode(msg_data) != config.OpCode.SK_CONFIRM:
            return False
        
        sk_confirm = SessionKeyConfirmMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
        
        # Verify HMAC
        data = (sk_confirm.id_drone + str(sk_confirm.ts)).encode('utf-8')
        if utils.verify_hmac(session_key, data, sk_confirm.hmac_tag):
            print(f"[MockMCC] SK confirmation verified")
            # Send success
            send_message(client_socket, StatusMessage(config.OpCode.SUCCESS, "OK"))
            return True
        return False
    
    def stop(self):
        """Stop server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class MockDrone:
    """Mock Drone for testing"""
    def __init__(self, drone_id: str):
        self.drone_id = drone_id
        self.socket = None
        self.keypair = None
        self.mcc_public_key = None
        self.p = None
        self.g = None
    
    def connect(self, port: int = 9998):
        """Connect to MCC"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("127.0.0.1", port))
        print(f"[{self.drone_id}] Connected")
    
    def receive_parameters(self):
        """Receive parameters"""
        msg_data = receive_message(self.socket)
        if not msg_data or get_opcode(msg_data) != config.OpCode.PARAM_INIT:
            return False
        
        param_msg = ParameterInitMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
        self.p = param_msg.p
        self.g = param_msg.g
        self.mcc_public_key = (param_msg.p, param_msg.g, param_msg.y_mcc)
        
        # Generate own keypair
        x = crypto_utils.secrets.randbelow(self.p - 2) + 1
        y = pow(self.g, x, self.p)
        self.keypair = crypto_utils.ElGamalKeyPair(self.p, self.g, x, y)
        
        print(f"[{self.drone_id}] Received parameters")
        return True
    
    def send_auth_request(self):
        """Send authentication request"""
        # Generate shared secret
        k_di_mcc = utils.generate_random_bytes(32)
        k_di_mcc_int = crypto_utils.bytes_to_int(k_di_mcc)
        
        # Encrypt
        c_i = ElGamal.encrypt(k_di_mcc_int, self.mcc_public_key)
        
        # Sign
        ts_i = utils.current_timestamp()
        rn_i = utils.generate_random_bytes(32)
        signed_data = (
            str(ts_i) + rn_i.hex() + self.drone_id +
            str(c_i[0]) + str(c_i[1])
        ).encode('utf-8')
        sig_i = ElGamal.sign(crypto_utils.hash_message(signed_data), self.keypair)
        
        # Send
        auth_req = AuthRequestMessage(ts_i, rn_i, self.drone_id, c_i, sig_i, self.keypair.y)
        send_message(self.socket, auth_req)
        print(f"[{self.drone_id}] Sent auth request")
        
        return k_di_mcc, ts_i, rn_i
    
    def receive_auth_response(self, k_di_mcc):
        """Receive authentication response"""
        msg_data = receive_message(self.socket)
        if not msg_data or get_opcode(msg_data) != config.OpCode.AUTH_RES:
            return None
        
        auth_res = AuthResponseMessage.from_bytes(json.dumps(msg_data).encode('utf-8'))
        
        # Verify signature
        signed_data = (
            str(auth_res.ts) + auth_res.rn.hex() + auth_res.id_mcc +
            str(auth_res.ciphertext[0]) + str(auth_res.ciphertext[1])
        ).encode('utf-8')
        if not ElGamal.verify(
            crypto_utils.hash_message(signed_data),
            auth_res.signature,
            self.mcc_public_key
        ):
            print(f"[{self.drone_id}] Signature verification failed")
            return None
        
        # Decrypt
        k_back_int = ElGamal.decrypt(auth_res.ciphertext, self.keypair)
        k_back = crypto_utils.int_to_bytes(k_back_int, 32)
        
        if k_back != k_di_mcc:
            print(f"[{self.drone_id}] Shared secret mismatch")
            return None
        
        print(f"[{self.drone_id}] Received auth response")
        return auth_res.ts, auth_res.rn
    
    def send_sk_confirm(self, session_key):
        """Send session key confirmation"""
        ts_final = utils.current_timestamp()
        data = (self.drone_id + str(ts_final)).encode('utf-8')
        hmac_tag = utils.compute_hmac(session_key, data)
        
        sk_confirm = SessionKeyConfirmMessage(self.drone_id, ts_final, hmac_tag)
        send_message(self.socket, sk_confirm)
        print(f"[{self.drone_id}] Sent SK confirmation")
    
    def receive_success(self):
        """Receive success message"""
        msg_data = receive_message(self.socket)
        if msg_data and get_opcode(msg_data) == config.OpCode.SUCCESS:
            print(f"[{self.drone_id}] Authentication complete")
            return True
        return False
    
    def disconnect(self):
        """Disconnect"""
        if self.socket:
            self.socket.close()


def test_phase0_parameter_init():
    """Test Phase 0: Parameter Initialization"""
    print("\n[INT TEST 1] Phase 0: Parameter Initialization")
    try:
        mcc = MockMCC()
        mcc.start(port=9991)
        
        success = [False]
        
        # Start drone in thread
        def drone_thread():
            try:
                drone = MockDrone("TEST_DRONE_1")
                drone.connect(port=9991)
                if drone.receive_parameters():
                    success[0] = True
                drone.disconnect()
            except Exception as e:
                print(f"Drone error: {e}")
        
        # Start drone thread
        dt = threading.Thread(target=drone_thread)
        dt.start()
        
        # Accept connection and send parameters
        client = mcc.accept_connection()
        mcc.send_parameters(client)
        
        # Wait for drone thread
        dt.join(timeout=5)
        
        client.close()
        mcc.stop()
        
        if success[0]:
            print("  ✓ Parameter exchange successful")
            results.record("Phase 0: Parameter Initialization", True)
        else:
            results.record("Phase 0: Parameter Initialization", False, "Drone didn't complete")
    except Exception as e:
        results.record("Phase 0: Parameter Initialization", False, str(e))


def test_full_authentication_flow():
    """Test Complete Authentication Flow"""
    print("\n[INT TEST 2] Complete Authentication Flow (Phase 0-2)")
    try:
        mcc = MockMCC()
        mcc.start(port=9992)
        
        success = [False]
        
        def drone_process():
            try:
                drone = MockDrone("TEST_DRONE_2")
                drone.connect(port=9992)
                
                # Phase 0
                if not drone.receive_parameters():
                    return
                
                # Phase 1A
                k_di_mcc, ts_i, rn_i = drone.send_auth_request()
                
                # Phase 1B
                result = drone.receive_auth_response(k_di_mcc)
                if not result:
                    return
                ts_mcc, rn_mcc = result
                
                # Phase 2
                session_key = utils.derive_session_key(k_di_mcc, ts_i, ts_mcc, rn_i, rn_mcc)
                drone.send_sk_confirm(session_key)
                
                if drone.receive_success():
                    success[0] = True
                
                drone.disconnect()
            except Exception as e:
                print(f"Drone error: {e}")
        
        # Start drone thread
        drone_thread = threading.Thread(target=drone_process)
        drone_thread.start()
        
        # MCC side
        client = mcc.accept_connection()
        mcc.send_parameters(client)
        
        auth_req = mcc.receive_auth_request(client)
        if not auth_req:
            raise Exception("Failed to receive auth request")
        
        k_di_mcc, ts_i, ts_mcc, rn_i, rn_mcc = mcc.send_auth_response(client, auth_req)
        session_key = utils.derive_session_key(k_di_mcc, ts_i, ts_mcc, rn_i, rn_mcc)
        
        if not mcc.receive_sk_confirm(client, session_key):
            raise Exception("SK confirmation failed")
        
        # Wait for drone thread
        drone_thread.join(timeout=5)
        
        client.close()
        mcc.stop()
        
        if success[0]:
            print("  ✓ Phase 0: Parameter initialization")
            print("  ✓ Phase 1A: Authentication request")
            print("  ✓ Phase 1B: Authentication response")
            print("  ✓ Phase 2: Session key confirmation")
            results.record("Complete Authentication Flow", True)
        else:
            results.record("Complete Authentication Flow", False, "Drone didn't complete")
    except Exception as e:
        results.record("Complete Authentication Flow", False, str(e))


def test_signature_verification():
    """Test Digital Signature Verification in Protocol"""
    print("\n[INT TEST 3] Digital Signature Verification")
    try:
        # Generate two keypairs
        keypair1 = ElGamal.generate_keypair(512, skip_check=True)
        keypair2 = ElGamal.generate_keypair(512, skip_check=True)
        
        # Message
        msg = b"Test authentication message"
        msg_hash = crypto_utils.hash_message(msg)
        
        # Sign with keypair1
        signature = ElGamal.sign(msg_hash, keypair1)
        
        # Verify with correct public key
        if not ElGamal.verify(msg_hash, signature, keypair1.get_public_key()):
            results.record("Signature Verification", False, "Valid signature rejected")
            return
        
        # Verify with wrong public key (should fail)
        if ElGamal.verify(msg_hash, signature, keypair2.get_public_key()):
            results.record("Signature Verification", False, "Signature accepted with wrong key")
            return
        
        print("  ✓ Valid signature accepted")
        print("  ✓ Signature with wrong key rejected")
        results.record("Digital Signature Verification", True)
    except Exception as e:
        results.record("Digital Signature Verification", False, str(e))


def test_replay_attack_prevention():
    """Test Timestamp-based Replay Attack Prevention"""
    print("\n[INT TEST 4] Replay Attack Prevention")
    try:
        # Create message with old timestamp
        old_ts = utils.current_timestamp() - 120  # 2 minutes old
        
        # Should be rejected
        if utils.validate_timestamp(old_ts):
            results.record("Replay Attack Prevention", False, "Old timestamp accepted")
            return
        
        # Create message with current timestamp
        current_ts = utils.current_timestamp()
        
        # Should be accepted
        if not utils.validate_timestamp(current_ts):
            results.record("Replay Attack Prevention", False, "Current timestamp rejected")
            return
        
        print("  ✓ Old timestamps rejected (replay prevention)")
        print("  ✓ Current timestamps accepted")
        results.record("Replay Attack Prevention", True)
    except Exception as e:
        results.record("Replay Attack Prevention", False, str(e))


def test_session_key_uniqueness():
    """Test Session Key Uniqueness"""
    print("\n[INT TEST 5] Session Key Uniqueness")
    try:
        k = utils.generate_random_bytes(32)
        ts1 = utils.current_timestamp()
        time.sleep(0.01)
        ts2 = utils.current_timestamp()
        rn1 = utils.generate_random_bytes(32)
        rn2 = utils.generate_random_bytes(32)
        
        # Same parameters should give same key
        sk1 = utils.derive_session_key(k, ts1, ts2, rn1, rn2)
        sk1_dup = utils.derive_session_key(k, ts1, ts2, rn1, rn2)
        
        if sk1 != sk1_dup:
            results.record("Session Key Uniqueness", False, "Non-deterministic derivation")
            return
        
        # Different nonce should give different key
        sk2 = utils.derive_session_key(k, ts1, ts2, rn2, rn2)
        if sk1 == sk2:
            results.record("Session Key Uniqueness", False, "Same key for different nonces")
            return
        
        # Different timestamp should give different key
        sk3 = utils.derive_session_key(k, ts1 + 1, ts2, rn1, rn2)
        if sk1 == sk3:
            results.record("Session Key Uniqueness", False, "Same key for different timestamps")
            return
        
        print("  ✓ Deterministic derivation")
        print("  ✓ Different nonces produce different keys")
        print("  ✓ Different timestamps produce different keys")
        results.record("Session Key Uniqueness", True)
    except Exception as e:
        results.record("Session Key Uniqueness", False, str(e))


def run_all_integration_tests():
    """Run all integration tests"""
    print("╔════════════════════════════════════════════════════════════╗")
    print("║       UAV C2 System - Integration Test Suite              ║")
    print("╚════════════════════════════════════════════════════════════╝")
    
    test_phase0_parameter_init()
    test_full_authentication_flow()
    test_signature_verification()
    test_replay_attack_prevention()
    test_session_key_uniqueness()
    
    results.print_summary()
    
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all_integration_tests())
