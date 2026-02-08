#!/usr/bin/env python3
"""
Comprehensive Test Suite for UAV C2 System
Tests all cryptographic primitives, protocol phases, and system functionality
"""

import sys
import time
import socket
import threading
from typing import Tuple, List
import hashlib

# Import system modules
import config
import utils
import crypto_utils
from crypto_utils import ElGamal, CryptoUtils, ElGamalKeyPair


class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def record(self, name: str, passed: bool, details: str = ""):
        self.tests.append({
            'name': name,
            'passed': passed,
            'details': details
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        for test in self.tests:
            status = "✓ PASS" if test['passed'] else "✗ FAIL"
            print(f"{status}: {test['name']}")
            if test['details']:
                print(f"       {test['details']}")
        print("="*70)
        print(f"Total: {self.passed + self.failed} | Passed: {self.passed} | Failed: {self.failed}")
        print("="*70)


results = TestResults()


def test_miller_rabin():
    """Test 1: Miller-Rabin Primality Test"""
    print("\n[TEST 1] Miller-Rabin Primality Test")
    try:
        # Test known primes
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        for p in primes:
            if not CryptoUtils.miller_rabin(p, k=5):
                results.record("Miller-Rabin: Known primes", False, f"Failed for prime {p}")
                return
        
        # Test known composites
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20]
        for c in composites:
            if CryptoUtils.miller_rabin(c, k=5):
                results.record("Miller-Rabin: Known composites", False, f"Failed for composite {c}")
                return
        
        print("  ✓ All known primes correctly identified")
        print("  ✓ All known composites correctly rejected")
        results.record("Miller-Rabin Primality Test", True)
    except Exception as e:
        results.record("Miller-Rabin Primality Test", False, str(e))


def test_prime_generation():
    """Test 2: Prime Generation (various bit lengths)"""
    print("\n[TEST 2] Prime Generation")
    try:
        bit_sizes = [64, 128, 256]
        for bits in bit_sizes:
            print(f"  Generating {bits}-bit prime...")
            p = CryptoUtils.generate_prime(bits)
            
            # Verify bit length
            if p.bit_length() != bits:
                results.record(f"Prime Generation ({bits}-bit)", False, 
                             f"Expected {bits} bits, got {p.bit_length()}")
                return
            
            # Verify primality
            if not CryptoUtils.miller_rabin(p, k=40):
                results.record(f"Prime Generation ({bits}-bit)", False, "Generated non-prime")
                return
            
            print(f"    ✓ Generated valid {bits}-bit prime")
        
        results.record("Prime Generation (64-256 bit)", True)
    except Exception as e:
        results.record("Prime Generation", False, str(e))


def test_modular_inverse():
    """Test 3: Modular Inverse (Extended Euclidean)"""
    print("\n[TEST 3] Modular Inverse")
    try:
        test_cases = [
            (7, 26, 15),      # 7 * 15 ≡ 1 (mod 26)
            (3, 11, 4),       # 3 * 4 ≡ 1 (mod 11)
            (5, 14, 3),       # 5 * 3 ≡ 1 (mod 14)
        ]
        
        for a, m, expected in test_cases:
            inv = CryptoUtils.mod_inverse(a, m)
            if inv != expected:
                results.record("Modular Inverse", False, 
                             f"mod_inverse({a}, {m}) = {inv}, expected {expected}")
                return
            
            # Verify: (a * inv) % m == 1
            if (a * inv) % m != 1:
                results.record("Modular Inverse", False, 
                             f"({a} * {inv}) mod {m} != 1")
                return
        
        # Test with large numbers (2048-bit prime)
        print("  Testing with 2048-bit numbers...")
        # Use a known large prime: 2^2048 - 1640729 (a Mersenne-like prime)
        # For testing, we'll just use a large coprime
        p = 2**2048 - 1640729
        a = 12345678901234567890
        try:
            inv = CryptoUtils.mod_inverse(a, p)
            if (a * inv) % p != 1:
                results.record("Modular Inverse", False, "Failed with large numbers")
                return
        except ValueError:
            # If no inverse exists, that's okay - check GCD
            if CryptoUtils.gcd(a, p) != 1:
                # Expected - no inverse when GCD != 1
                pass
            else:
                results.record("Modular Inverse", False, "Inverse should exist but didn't")
                return
        
        print("  ✓ All small test cases passed")
        print("  ✓ Large number (2048-bit) test passed")
        results.record("Modular Inverse", True)
    except Exception as e:
        results.record("Modular Inverse", False, str(e))


def test_gcd():
    """Test 4: GCD Calculation"""
    print("\n[TEST 4] GCD Calculation")
    try:
        test_cases = [
            (48, 18, 6),
            (100, 35, 5),
            (17, 13, 1),  # Coprime
            (270, 192, 6),
        ]
        
        for a, b, expected in test_cases:
            result = CryptoUtils.gcd(a, b)
            if result != expected:
                results.record("GCD Calculation", False, 
                             f"gcd({a}, {b}) = {result}, expected {expected}")
                return
        
        print("  ✓ All GCD test cases passed")
        results.record("GCD Calculation", True)
    except Exception as e:
        results.record("GCD Calculation", False, str(e))


def test_elgamal_key_generation():
    """Test 5: ElGamal Key Generation"""
    print("\n[TEST 5] ElGamal Key Generation (512-bit for speed)")
    try:
        keypair = ElGamal.generate_keypair(512, skip_check=True)
        
        # Verify key components
        if keypair.p <= 0:
            results.record("ElGamal Key Generation", False, "Invalid prime p")
            return
        
        if keypair.g <= 0:
            results.record("ElGamal Key Generation", False, "Invalid generator g")
            return
        
        if not (1 <= keypair.x < keypair.p - 1):
            results.record("ElGamal Key Generation", False, "Invalid private key x")
            return
        
        # Verify y = g^x mod p
        expected_y = pow(keypair.g, keypair.x, keypair.p)
        if keypair.y != expected_y:
            results.record("ElGamal Key Generation", False, "Public key y != g^x mod p")
            return
        
        print(f"  ✓ Prime p: {keypair.p.bit_length()} bits")
        print(f"  ✓ Generator g: {keypair.g}")
        print(f"  ✓ Private key x: valid range")
        print(f"  ✓ Public key y: correctly computed")
        results.record("ElGamal Key Generation", True)
    except Exception as e:
        results.record("ElGamal Key Generation", False, str(e))


def test_elgamal_encryption_decryption():
    """Test 6: ElGamal Encryption/Decryption"""
    print("\n[TEST 6] ElGamal Encryption/Decryption")
    try:
        # Generate keypair
        keypair = ElGamal.generate_keypair(512, skip_check=True)
        public_key = keypair.get_public_key()
        
        # Test messages
        test_messages = [
            123456789,
            999999999999,
            12345678901234567890,
        ]
        
        for msg in test_messages:
            # Encrypt
            ciphertext = ElGamal.encrypt(msg, public_key)
            c1, c2 = ciphertext
            
            # Verify ciphertext components are in valid range
            if not (0 < c1 < keypair.p and 0 < c2 < keypair.p):
                results.record("ElGamal Encryption/Decryption", False, 
                             "Ciphertext out of valid range")
                return
            
            # Decrypt
            decrypted = ElGamal.decrypt(ciphertext, keypair)
            
            # Verify
            if decrypted != msg:
                results.record("ElGamal Encryption/Decryption", False, 
                             f"Decryption failed: {msg} != {decrypted}")
                return
            
            print(f"  ✓ Encrypt/Decrypt: {msg}")
        
        results.record("ElGamal Encryption/Decryption", True)
    except Exception as e:
        results.record("ElGamal Encryption/Decryption", False, str(e))


def test_elgamal_signing_verification():
    """Test 7: ElGamal Digital Signatures"""
    print("\n[TEST 7] ElGamal Digital Signatures")
    try:
        # Generate keypair
        keypair = ElGamal.generate_keypair(512, skip_check=True)
        public_key = keypair.get_public_key()
        
        # Test messages
        messages = [
            b"Hello, UAV world!",
            b"Secure authentication message",
            b"Test signature verification",
        ]
        
        for msg in messages:
            # Hash message
            msg_hash = crypto_utils.hash_message(msg)
            
            # Sign
            signature = ElGamal.sign(msg_hash, keypair)
            r, s = signature
            
            # Verify signature components are in valid range
            if not (0 < r < keypair.p):
                results.record("ElGamal Signatures", False, "Signature r out of range")
                return
            
            # Verify signature
            if not ElGamal.verify(msg_hash, signature, public_key):
                results.record("ElGamal Signatures", False, "Valid signature rejected")
                return
            
            # Test with wrong message (should fail)
            wrong_hash = crypto_utils.hash_message(b"Wrong message")
            if ElGamal.verify(wrong_hash, signature, public_key):
                results.record("ElGamal Signatures", False, "Invalid signature accepted")
                return
            
            print(f"  ✓ Sign/Verify: {msg.decode()[:30]}...")
        
        results.record("ElGamal Digital Signatures", True)
    except Exception as e:
        results.record("ElGamal Digital Signatures", False, str(e))


def test_aes_encryption():
    """Test 8: AES-256-CBC Encryption"""
    print("\n[TEST 8] AES-256-CBC Encryption")
    try:
        key = utils.generate_random_bytes(32)
        
        test_messages = [
            b"Short message",
            b"A" * 100,  # Longer message
            b"Special chars: !@#$%^&*()",
        ]
        
        for plaintext in test_messages:
            # Encrypt
            ciphertext = utils.aes_encrypt(key, plaintext)
            
            # Verify IV is prepended (first 16 bytes)
            if len(ciphertext) < 16:
                results.record("AES-256-CBC", False, "Ciphertext too short")
                return
            
            # Decrypt
            decrypted = utils.aes_decrypt(key, ciphertext)
            
            # Verify
            if decrypted != plaintext:
                results.record("AES-256-CBC", False, "Decryption mismatch")
                return
            
            print(f"  ✓ AES Encrypt/Decrypt: {len(plaintext)} bytes")
        
        results.record("AES-256-CBC Encryption", True)
    except Exception as e:
        results.record("AES-256-CBC Encryption", False, str(e))


def test_hmac():
    """Test 9: HMAC-SHA256"""
    print("\n[TEST 9] HMAC-SHA256")
    try:
        key = utils.generate_random_bytes(32)
        data = b"Test data for HMAC"
        
        # Compute HMAC
        tag = utils.compute_hmac(key, data)
        
        # Verify correct tag
        if not utils.verify_hmac(key, data, tag):
            results.record("HMAC-SHA256", False, "Valid HMAC rejected")
            return
        
        # Verify wrong data fails
        if utils.verify_hmac(key, b"Wrong data", tag):
            results.record("HMAC-SHA256", False, "Invalid HMAC accepted")
            return
        
        # Verify wrong key fails
        wrong_key = utils.generate_random_bytes(32)
        if utils.verify_hmac(wrong_key, data, tag):
            results.record("HMAC-SHA256", False, "HMAC with wrong key accepted")
            return
        
        print("  ✓ HMAC computation and verification")
        print("  ✓ Wrong data detection")
        print("  ✓ Wrong key detection")
        results.record("HMAC-SHA256", True)
    except Exception as e:
        results.record("HMAC-SHA256", False, str(e))


def test_session_key_derivation():
    """Test 10: Session Key Derivation"""
    print("\n[TEST 10] Session Key Derivation")
    try:
        k_di_mcc = utils.generate_random_bytes(32)
        ts_i = utils.current_timestamp()
        ts_mcc = utils.current_timestamp()
        rn_i = utils.generate_random_bytes(32)
        rn_mcc = utils.generate_random_bytes(32)
        
        # Derive session key
        sk = utils.derive_session_key(k_di_mcc, ts_i, ts_mcc, rn_i, rn_mcc)
        
        # Verify session key is 32 bytes
        if len(sk) != 32:
            results.record("Session Key Derivation", False, 
                         f"Expected 32 bytes, got {len(sk)}")
            return
        
        # Verify same inputs produce same key
        sk2 = utils.derive_session_key(k_di_mcc, ts_i, ts_mcc, rn_i, rn_mcc)
        if sk != sk2:
            results.record("Session Key Derivation", False, "Non-deterministic derivation")
            return
        
        # Verify different inputs produce different keys
        sk3 = utils.derive_session_key(k_di_mcc, ts_i + 1, ts_mcc, rn_i, rn_mcc)
        if sk == sk3:
            results.record("Session Key Derivation", False, "Same key for different inputs")
            return
        
        print("  ✓ Session key derivation (32 bytes)")
        print("  ✓ Deterministic derivation")
        print("  ✓ Different inputs produce different keys")
        results.record("Session Key Derivation", True)
    except Exception as e:
        results.record("Session Key Derivation", False, str(e))


def test_timestamp_validation():
    """Test 11: Timestamp Validation"""
    print("\n[TEST 11] Timestamp Validation")
    try:
        current = utils.current_timestamp()
        
        # Current timestamp should be valid
        if not utils.validate_timestamp(current):
            results.record("Timestamp Validation", False, "Current timestamp rejected")
            return
        
        # Recent timestamp should be valid
        recent = current - 30
        if not utils.validate_timestamp(recent):
            results.record("Timestamp Validation", False, "Recent timestamp rejected")
            return
        
        # Old timestamp should be invalid
        old = current - 120  # Beyond tolerance
        if utils.validate_timestamp(old):
            results.record("Timestamp Validation", False, "Old timestamp accepted")
            return
        
        # Future timestamp within tolerance should be valid
        future_near = current + 30
        if not utils.validate_timestamp(future_near):
            results.record("Timestamp Validation", False, "Near future timestamp rejected")
            return
        
        print("  ✓ Current timestamp validation")
        print("  ✓ Recent timestamp validation")
        print("  ✓ Old timestamp rejection")
        print("  ✓ Near future timestamp validation")
        results.record("Timestamp Validation", True)
    except Exception as e:
        results.record("Timestamp Validation", False, str(e))


def test_protocol_messages():
    """Test 12: Protocol Message Serialization"""
    print("\n[TEST 12] Protocol Message Serialization")
    try:
        from protocol import (
            ParameterInitMessage, AuthRequestMessage, AuthResponseMessage,
            SessionKeyConfirmMessage, StatusMessage, GroupKeyMessage,
            GroupCommandMessage, ShutdownMessage
        )
        
        # Test ParameterInitMessage
        msg1 = ParameterInitMessage(12345, 2, 2048, utils.current_timestamp(), "MCC", 67890)
        data1 = msg1.to_bytes()
        msg1_restored = ParameterInitMessage.from_bytes(data1)
        if msg1_restored.p != 12345 or msg1_restored.y_mcc != 67890:
            results.record("Protocol Messages", False, "ParameterInitMessage serialization failed")
            return
        
        # Test AuthRequestMessage
        msg2 = AuthRequestMessage(
            utils.current_timestamp(),
            utils.generate_random_bytes(32),
            "DRONE_001",
            (111, 222),
            (333, 444),
            555
        )
        data2 = msg2.to_bytes()
        msg2_restored = AuthRequestMessage.from_bytes(data2)
        if msg2_restored.id_drone != "DRONE_001" or msg2_restored.y_drone != 555:
            results.record("Protocol Messages", False, "AuthRequestMessage serialization failed")
            return
        
        # Test StatusMessage
        msg3 = StatusMessage(config.OpCode.SUCCESS, "Test message")
        data3 = msg3.to_bytes()
        msg3_restored = StatusMessage.from_bytes(data3)
        if msg3_restored.message != "Test message":
            results.record("Protocol Messages", False, "StatusMessage serialization failed")
            return
        
        print("  ✓ ParameterInitMessage serialization")
        print("  ✓ AuthRequestMessage serialization")
        print("  ✓ StatusMessage serialization")
        results.record("Protocol Message Serialization", True)
    except Exception as e:
        results.record("Protocol Message Serialization", False, str(e))


def test_security_level_validation():
    """Test 13: Security Level Validation"""
    print("\n[TEST 13] Security Level Validation")
    try:
        # Test that 2048-bit is enforced
        try:
            keypair = ElGamal.generate_keypair(1024, skip_check=False)
            results.record("Security Level Validation", False, 
                         "Accepted security level < 2048")
            return
        except ValueError:
            pass  # Expected
        
        # Test that 2048-bit is accepted
        try:
            # Just verify it doesn't raise an error (don't actually generate for speed)
            if config.SECURITY_LEVEL < 2048:
                results.record("Security Level Validation", False, 
                             f"Config SECURITY_LEVEL is {config.SECURITY_LEVEL}, should be >= 2048")
                return
        except Exception as e:
            results.record("Security Level Validation", False, str(e))
            return
        
        print("  ✓ Security level < 2048 rejected")
        print(f"  ✓ Config SECURITY_LEVEL = {config.SECURITY_LEVEL}")
        results.record("Security Level Validation", True)
    except Exception as e:
        results.record("Security Level Validation", False, str(e))


def test_opcode_definitions():
    """Test 14: OpCode Definitions"""
    print("\n[TEST 14] OpCode Definitions")
    try:
        required_opcodes = {
            'PARAM_INIT': 10,
            'AUTH_REQ': 20,
            'AUTH_RES': 30,
            'SK_CONFIRM': 40,
            'SUCCESS': 50,
            'ERR_MISMATCH': 60,
            'GROUP_KEY': 70,
            'GROUP_CMD': 80,
            'SHUTDOWN': 90,
        }
        
        for name, expected_value in required_opcodes.items():
            if not hasattr(config.OpCode, name):
                results.record("OpCode Definitions", False, f"OpCode.{name} not defined")
                return
            
            actual_value = getattr(config.OpCode, name)
            if actual_value != expected_value:
                results.record("OpCode Definitions", False, 
                             f"OpCode.{name} = {actual_value}, expected {expected_value}")
                return
        
        print("  ✓ All required OpCodes defined with correct values")
        results.record("OpCode Definitions", True)
    except Exception as e:
        results.record("OpCode Definitions", False, str(e))


def run_all_tests():
    """Run all tests"""
    print("╔════════════════════════════════════════════════════════════╗")
    print("║       UAV C2 System - Comprehensive Test Suite            ║")
    print("╚════════════════════════════════════════════════════════════╝")
    
    # Cryptographic Primitive Tests
    print("\n" + "="*70)
    print("CRYPTOGRAPHIC PRIMITIVE TESTS")
    print("="*70)
    
    test_miller_rabin()
    test_prime_generation()
    test_modular_inverse()
    test_gcd()
    test_elgamal_key_generation()
    test_elgamal_encryption_decryption()
    test_elgamal_signing_verification()
    
    # Symmetric Cryptography Tests
    print("\n" + "="*70)
    print("SYMMETRIC CRYPTOGRAPHY TESTS")
    print("="*70)
    
    test_aes_encryption()
    test_hmac()
    test_session_key_derivation()
    
    # Protocol Tests
    print("\n" + "="*70)
    print("PROTOCOL TESTS")
    print("="*70)
    
    test_timestamp_validation()
    test_protocol_messages()
    test_security_level_validation()
    test_opcode_definitions()
    
    # Print summary
    results.print_summary()
    
    # Return exit code
    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
