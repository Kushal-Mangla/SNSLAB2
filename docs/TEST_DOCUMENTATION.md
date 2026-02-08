# UAV C2 System - Test Documentation

## Overview
This document provides detailed information about all tests in the UAV Command and Control system test suite.

---

## Unit Tests (`test_suite.py`)

### 1. Miller-Rabin Primality Test
**Purpose**: Verify the Miller-Rabin probabilistic primality test algorithm

**What it tests**:
- Detection of known prime numbers (small primes: 2, 3, 5, 7, 11, 13)
- Detection of known composite numbers (4, 6, 8, 9, 10, 12)
- Rejection of 0 and 1 as non-prime
- Uses 40 rounds for high accuracy (error probability < 2^-80)

**Why it matters**: 
- Foundation of ElGamal key generation
- Must correctly identify primes to ensure cryptographic security
- False positives would lead to insecure keys

**Expected Result**: All known primes should pass, all composites should fail

---

### 2. Prime Generation (64-bit)
**Purpose**: Verify generation of 64-bit prime numbers

**What it tests**:
- Generated number is actually prime (via Miller-Rabin)
- Generated number has correct bit length (64 bits)
- Non-deterministic (different values on multiple calls)

**Why it matters**:
- Quick test of prime generation pipeline
- Used for small key components

**Expected Result**: 64-bit prime number that passes primality test

---

### 3. Prime Generation (128-bit)
**Purpose**: Verify generation of 128-bit prime numbers

**What it tests**:
- Generated number is prime
- Generated number has correct bit length (128 bits)
- Generation completes in reasonable time

**Why it matters**:
- Medium-sized primes for intermediate testing
- Validates scalability of generation algorithm

**Expected Result**: 128-bit prime number that passes primality test

---

### 4. Prime Generation (256-bit)
**Purpose**: Verify generation of 256-bit prime numbers

**What it tests**:
- Generated number is prime
- Generated number has correct bit length (256 bits)
- Generation remains efficient at larger sizes

**Why it matters**:
- Larger primes closer to production requirements
- Tests performance at scale

**Expected Result**: 256-bit prime number that passes primality test

---

### 5. Modular Inverse
**Purpose**: Verify modular multiplicative inverse calculation

**What it tests**:
- Correct computation: `(a * mod_inverse(a, m)) % m == 1`
- Uses Python's built-in `pow(a, -1, m)` to avoid recursion limits
- Handles various input sizes

**Test Cases**:
- `mod_inverse(3, 11) == 4` because `(3 * 4) % 11 = 1`
- `mod_inverse(10, 17) == 12` because `(10 * 12) % 17 = 1`
- Multiple random cases with verification

**Why it matters**:
- Critical for ElGamal decryption
- Must be mathematically correct for system to work
- Previous recursive implementation hit recursion limits with 2048-bit numbers

**Expected Result**: All inverses satisfy `(a * inv) % m == 1`

---

### 6. GCD (Greatest Common Divisor)
**Purpose**: Verify GCD calculation using Euclidean algorithm

**What it tests**:
- Correct computation for known pairs
- Edge cases (GCD with 1, GCD with 0)

**Test Cases**:
- `gcd(48, 18) = 6`
- `gcd(100, 50) = 50`
- `gcd(17, 19) = 1` (coprime numbers)

**Why it matters**:
- Used in modular inverse calculation
- Required for ElGamal parameter validation

**Expected Result**: Correct GCD values for all test cases

---

### 7. ElGamal Key Generation
**Purpose**: Verify ElGamal public/private keypair generation

**What it tests**:
- Generated prime `p` passes primality test
- Generator `g` is in valid range `[2, p-1]`
- Private key `x` is in valid range `[1, p-1]`
- Public key `y = g^x mod p` is computed correctly
- Key generation completes successfully at 512 bits (fast test)

**Why it matters**:
- Foundation of all ElGamal operations
- Keys must satisfy mathematical requirements
- Invalid keys would break encryption/signatures

**Expected Result**: Valid ElGamal keypair with correct relationships

---

### 8. ElGamal Encryption/Decryption
**Purpose**: Verify ElGamal encryption and decryption work correctly

**What it tests**:
- Plaintext → Encryption → Decryption → Original plaintext
- Encryption produces valid ciphertext pair (c1, c2)
- Decryption correctly recovers original message
- Works with various message sizes

**Test Process**:
1. Generate keypair (512-bit for speed)
2. Encrypt a test message
3. Decrypt the ciphertext
4. Verify decrypted == original

**Why it matters**:
- Core cryptographic operation for secure communication
- Used to protect shared secrets (K_Di,MCC)
- Must be lossless and secure

**Expected Result**: Decrypted plaintext matches original

---

### 9. ElGamal Digital Signatures
**Purpose**: Verify ElGamal signature generation and verification

**What it tests**:
- Signature generation produces valid (r, s) pair
- Valid signatures pass verification
- Invalid signatures fail verification
- Signatures with wrong public key fail verification
- Modified messages fail verification

**Test Cases**:
1. Sign a message with keypair A
2. Verify with public key A → Should PASS
3. Sign a message with keypair A
4. Verify with public key B → Should FAIL
5. Sign a message, modify it
6. Verify modified message → Should FAIL

**Why it matters**:
- Provides authentication in protocol
- Prevents impersonation attacks
- Must reject invalid/forged signatures

**Expected Result**: Valid signatures accepted, invalid rejected

---

### 10. AES-256-CBC Encryption
**Purpose**: Verify AES symmetric encryption using pycryptodome

**What it tests**:
- Encryption produces ciphertext different from plaintext
- Decryption recovers original plaintext
- 256-bit key strength
- CBC mode with random IV
- PKCS7 padding

**Test Process**:
1. Generate random 32-byte (256-bit) key
2. Encrypt plaintext
3. Verify ciphertext ≠ plaintext
4. Decrypt ciphertext
5. Verify decrypted == original

**Why it matters**:
- Used for encrypting commands and data
- Group key encryption
- Efficient symmetric crypto for bulk data

**Expected Result**: Successful encryption/decryption cycle

---

### 11. HMAC-SHA256
**Purpose**: Verify HMAC message authentication

**What it tests**:
- HMAC generation produces 32-byte tag
- Valid HMACs pass verification
- Invalid HMACs fail verification
- Modified data fails verification
- Wrong key fails verification

**Test Cases**:
1. Compute HMAC with key K
2. Verify with same key → Should PASS
3. Modify data
4. Verify modified data → Should FAIL
5. Verify with different key → Should FAIL

**Why it matters**:
- Ensures message integrity
- Used in session key confirmation
- Prevents tampering attacks

**Expected Result**: Valid HMACs accepted, invalid rejected

---

### 12. Session Key Derivation
**Purpose**: Verify session key derivation from authentication parameters

**What it tests**:
- Derives 32-byte (256-bit) session key
- Uses: shared secret, timestamps, nonces
- Deterministic (same inputs → same output)
- Different inputs → different outputs

**Formula**: `SK = HMAC-SHA256(K_Di,MCC, TS_i || TS_MCC || RN_i || RN_MCC)`

**Test Process**:
1. Generate authentication parameters
2. Derive session key twice with same params
3. Verify keys match (deterministic)
4. Change one parameter, derive again
5. Verify new key is different

**Why it matters**:
- Creates unique session key for each authentication
- Combines freshness (timestamps, nonces) with shared secret
- Foundation of secure session communication

**Expected Result**: Correct key length, deterministic derivation

---

### 13. Timestamp Validation
**Purpose**: Verify timestamp-based replay attack prevention

**What it tests**:
- Current timestamps are accepted
- Old timestamps are rejected (> 60 seconds old)
- Boundary cases (exactly 60 seconds)

**Test Cases**:
1. Current timestamp → Should PASS
2. Timestamp from 2 minutes ago → Should FAIL
3. Timestamp from 30 seconds ago → Should PASS

**Why it matters**:
- Prevents replay attacks
- Attacker cannot reuse old messages
- Critical for protocol security

**Expected Result**: Only fresh timestamps accepted

---

### 14. Protocol Message Serialization
**Purpose**: Verify all protocol messages serialize/deserialize correctly

**What it tests for each message type**:
- Serialization to bytes
- Deserialization back to object
- Correct OpCode assignment
- All fields preserved through round-trip
- JSON encoding/decoding

**Message Types Tested**:
1. `ParameterInitMessage` (OpCode 0x01)
2. `AuthRequestMessage` (OpCode 0x02)
3. `AuthResponseMessage` (OpCode 0x03)
4. `SessionKeyConfirmMessage` (OpCode 0x04)
5. `StatusMessage` (OpCode 0x05)
6. `GroupKeyMessage` (OpCode 0x06)
7. `CommandMessage` (OpCode 0x07)

**Test Process for each**:
1. Create message with test data
2. Serialize to bytes
3. Parse bytes back to object
4. Verify all fields match original

**Why it matters**:
- Messages must survive network transmission
- No data loss or corruption
- Correct OpCode routing

**Expected Result**: All messages serialize/deserialize losslessly

---

### 15. Security Level Validation
**Purpose**: Verify 2048-bit minimum security level enforcement

**What it tests**:
- Key generation with SL < 2048 is rejected
- Key generation with SL >= 2048 succeeds
- Configuration enforces minimum

**Test Cases**:
1. Try to generate 1024-bit key → Should FAIL or warn
2. Try to generate 512-bit key → Should FAIL or warn
3. Generate 2048-bit key → Should SUCCEED

**Why it matters**:
- Assignment requires minimum 2048-bit security
- Prevents weak crypto
- Ensures compliance with specifications

**Expected Result**: Only keys >= 2048 bits allowed (or explicit override)

---

### 16. OpCode Definitions
**Purpose**: Verify all protocol OpCodes are correctly defined

**What it tests**:
- All 9 OpCodes have unique values
- OpCode values match specification:
  - 0x00: ERROR
  - 0x01: PARAM_INIT
  - 0x02: AUTH_REQ
  - 0x03: AUTH_RES
  - 0x04: SK_CONFIRM
  - 0x05: SUCCESS
  - 0x06: GROUP_KEY
  - 0x07: COMMAND
  - 0x08: ACK

**Why it matters**:
- OpCodes route messages to correct handlers
- Duplicate values would cause confusion
- Must match protocol specification

**Expected Result**: All OpCodes unique and correctly valued

---

## Integration Tests (`test_integration.py`)

### INT-1: Phase 0 - Parameter Initialization
**Purpose**: Test parameter exchange between MCC and drone

**What it tests**:
- MCC generates ElGamal parameters (p, g)
- MCC generates own keypair (x_MCC, y_MCC)
- MCC sends `ParameterInitMessage` with p, g, SL, timestamp, ID_MCC, y_MCC
- Drone receives and validates parameters
- Drone generates own keypair with received p, g

**Components Tested**:
- Socket communication
- Message serialization
- Parameter generation
- Key generation

**Why it matters**:
- First phase of protocol
- Establishes cryptographic parameters
- Both parties must agree on p, g

**Expected Result**: Drone successfully receives parameters and generates keypair

---

### INT-2: Complete Authentication Flow
**Purpose**: Test end-to-end authentication from Phase 0 to Phase 2

**What it tests**:

**Phase 0**: Parameter initialization
- MCC sends parameters
- Drone receives and generates keypair

**Phase 1A**: Authentication Request
- Drone generates shared secret K_Di,MCC (32 bytes)
- Drone encrypts K with MCC's public key: C_i = Enc_MCC(K)
- Drone signs (TS_i, RN_i, ID_i, C_i)
- Drone sends `AuthRequestMessage` with timestamp, nonce, ID, ciphertext, signature, y_drone

**Phase 1B**: Authentication Response
- MCC receives auth request
- MCC verifies drone's signature using y_drone
- MCC decrypts K_Di,MCC using its private key
- MCC generates RN_MCC
- MCC encrypts K back with drone's public key: C_MCC = Enc_Drone(K)
- MCC signs (TS_MCC, RN_MCC, ID_MCC, C_MCC)
- MCC sends `AuthResponseMessage`

- Drone receives auth response
- Drone verifies MCC's signature using y_MCC
- Drone decrypts and verifies K matches original

**Phase 2**: Session Key Confirmation
- Both derive session key: SK = HMAC(K, TS_i || TS_MCC || RN_i || RN_MCC)
- Drone computes HMAC_tag = HMAC-SHA256(SK, ID_i || TS_final)
- Drone sends `SessionKeyConfirmMessage`
- MCC verifies HMAC
- MCC sends `StatusMessage` (SUCCESS)

**Components Tested**:
- All 4 protocol phases
- ElGamal encryption/decryption (both directions)
- Digital signatures (both parties)
- Session key derivation
- HMAC verification
- Multi-threaded communication

**Why it matters**:
- Core security protocol
- Mutual authentication
- Prevents man-in-the-middle attacks
- Establishes secure session

**Expected Result**: Complete authentication with session key establishment

---

### INT-3: Digital Signature Verification
**Purpose**: Test signature verification in realistic protocol context

**What it tests**:
- Generate two separate keypairs
- Sign message with keypair A
- Verify with public key A → Should SUCCEED
- Verify with public key B → Should FAIL
- Signature verification prevents impersonation

**Why it matters**:
- Critical for authentication
- Prevents forged authentication messages
- Must reject signatures from wrong keys

**Expected Result**: Signatures verified only with correct public key

---

### INT-4: Replay Attack Prevention
**Purpose**: Test timestamp-based replay protection

**What it tests**:
- Messages with old timestamps (> 60 seconds) are rejected
- Messages with current timestamps are accepted
- Attacker cannot reuse captured messages

**Attack Scenario**:
1. Attacker captures `AuthRequestMessage` at time T
2. Attacker tries to replay it at time T+120 seconds
3. System should reject due to old timestamp

**Why it matters**:
- Prevents replay attacks
- Ensures message freshness
- Critical for protocol security

**Expected Result**: Old messages rejected, current messages accepted

---

### INT-5: Session Key Uniqueness
**Purpose**: Test that session keys are unique per session

**What it tests**:
- Same parameters → same session key (deterministic)
- Different nonces → different session keys
- Different timestamps → different session keys
- Each session gets unique key

**Test Cases**:
1. Derive SK with (K, TS1, TS2, RN1, RN2)
2. Derive again with same params → Should match
3. Derive with different nonce → Should differ
4. Derive with different timestamp → Should differ

**Why it matters**:
- Each session must be independent
- Compromising one session shouldn't affect others
- Freshness ensures forward secrecy properties

**Expected Result**: Deterministic derivation, unique keys per session

---

## System Tests (Manual)

### SYS-1: MCC Server Startup
**Purpose**: Verify MCC server starts correctly

**Steps**:
1. Run `./run_mcc.sh`
2. Check for "MCC Server started on port 5000"
3. Verify CLI prompt appears

**Expected**:
- Server binds to port 5000
- Ready to accept drone connections
- CLI responsive

---

### SYS-2: Drone Connection and Authentication
**Purpose**: Verify drone connects and authenticates with MCC

**Steps**:
1. Start MCC server
2. Run `./run_drone.sh DRONE_001`
3. Observe authentication sequence

**Expected**:
- Drone connects to MCC
- Parameter exchange completes
- Mutual authentication succeeds
- Session key established
- Drone enters ready state

---

### SYS-3: Multiple Concurrent Drones
**Purpose**: Test multi-drone fleet management

**Steps**:
1. Start MCC server
2. Start 3 drones: `./run_drone.sh DRONE_001`, `DRONE_002`, `DRONE_003`
3. On MCC CLI, run: `list`

**Expected**:
- All 3 drones authenticate successfully
- `list` command shows all 3 drones
- Each has unique session key
- All show "Ready" status

---

### SYS-4: Broadcast Command
**Purpose**: Test group key distribution and command broadcast

**Steps**:
1. Start MCC with 3 drones
2. On MCC CLI, run: `broadcast "MISSION: Return to base"`
3. Observe all drones

**Expected**:
- MCC aggregates group key from all session keys
- MCC encrypts command with group key
- All drones receive `GroupKeyMessage`
- All drones receive `CommandMessage`
- All drones decrypt and display command
- All drones send ACK

---

### SYS-5: Graceful Shutdown
**Purpose**: Test clean server shutdown

**Steps**:
1. Start MCC with connected drones
2. On MCC CLI, run: `shutdown`
3. Observe cleanup

**Expected**:
- MCC notifies all drones
- Drones disconnect gracefully
- MCC closes all sockets
- Process exits cleanly

---

## Attack Simulation Tests (`attacks.py` - To Be Created)

### ATK-1: Replay Attack
**Purpose**: Demonstrate replay attack is prevented

**Attack**:
1. Capture valid `AuthRequestMessage`
2. Wait > 60 seconds
3. Replay captured message

**Expected**: MCC rejects due to old timestamp

---

### ATK-2: Man-in-the-Middle (Parameter Tampering)
**Purpose**: Demonstrate MITM protection

**Attack**:
1. Intercept `ParameterInitMessage`
2. Replace p with attacker's weak prime
3. Forward modified message to drone

**Expected**: Drone detects signature mismatch or invalid parameters

---

### ATK-3: Unauthorized Drone
**Purpose**: Demonstrate authentication requirement

**Attack**:
1. Rogue drone connects to MCC
2. Sends invalid `AuthRequestMessage` with bad signature

**Expected**: MCC rejects authentication, drone cannot join fleet

---

### ATK-4: Command Injection
**Purpose**: Demonstrate encryption protection

**Attack**:
1. Capture encrypted `CommandMessage`
2. Modify ciphertext
3. Forward to drone

**Expected**: Drone decryption fails or HMAC verification fails

---

## Test Execution

### Running Unit Tests
```bash
python3 test_suite.py
```

### Running Integration Tests
```bash
python3 test_integration.py
```

### Running All Tests
```bash
python3 test_suite.py && python3 test_integration.py
```

---

## Test Coverage Summary

| Component | Unit Tests | Integration Tests | System Tests |
|-----------|-----------|-------------------|--------------|
| **Cryptographic Primitives** |
| Miller-Rabin | ✓ | | |
| Prime Generation | ✓ | | |
| Modular Inverse | ✓ | | |
| GCD | ✓ | | |
| ElGamal Keygen | ✓ | ✓ | |
| ElGamal Encrypt/Decrypt | ✓ | ✓ | |
| ElGamal Sign/Verify | ✓ | ✓ | |
| AES-256-CBC | ✓ | | ✓ |
| HMAC-SHA256 | ✓ | ✓ | |
| **Protocol** |
| Phase 0: Parameters | | ✓ | ✓ |
| Phase 1A: Auth Request | | ✓ | ✓ |
| Phase 1B: Auth Response | | ✓ | ✓ |
| Phase 2: SK Confirm | | ✓ | ✓ |
| Phase 3: Group Key | | | ✓ |
| Message Serialization | ✓ | | |
| OpCode Routing | ✓ | | |
| **Security** |
| Replay Prevention | ✓ | ✓ | ✓ |
| Signature Verification | ✓ | ✓ | ✓ |
| Session Key Uniqueness | | ✓ | |
| 2048-bit Enforcement | ✓ | | |
| **System** |
| Multi-threading | | ✓ | ✓ |
| Fleet Management | | | ✓ |
| CLI Commands | | | ✓ |
| Graceful Shutdown | | | ✓ |

**Total Coverage**: 35+ test cases across all layers

---

## Success Criteria

### Unit Tests
- ✓ All cryptographic primitives work correctly
- ✓ All message types serialize/deserialize
- ✓ Security parameters validated
- ✓ No mathematical errors

### Integration Tests
- ✓ Complete authentication flow succeeds
- ✓ Signatures verified correctly
- ✓ Replay attacks prevented
- ✓ Session keys unique and secure

### System Tests
- ✓ MCC handles multiple drones concurrently
- ✓ Broadcast commands reach all drones
- ✓ Group key encryption works
- ✓ Graceful error handling and shutdown

---

## Notes

1. **Performance**: Integration tests use 512-bit keys for speed. Production uses 2048-bit.

2. **Network Tests**: Integration tests use localhost (127.0.0.1) with different ports to avoid conflicts.

3. **Timing**: Timestamp tests may be sensitive to system time changes.

4. **Randomness**: Some tests use random values. Failures should be reproducible with same seed.

5. **Security**: This test suite validates correctness, not resistance to side-channel attacks.

---

*Generated for SNS Assignment 2 - Secure UAV Command and Control System*
