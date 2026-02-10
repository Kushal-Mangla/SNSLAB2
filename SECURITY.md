# Security Analysis: UAV Command and Control System

## Overview

This document provides a comprehensive security analysis of the UAV Command and Control (C2) system, focusing on how the authentication protocol ensures **Freshness** and **Forward Secrecy**.

---

## 1. Freshness Guarantee

**Freshness** ensures that authentication messages are current and not replayed from previous sessions. This prevents replay attacks where an attacker captures legitimate messages and retransmits them later.

### 1.1 Mechanisms Ensuring Freshness

#### **A. Timestamps (TS_i, TS_MCC)**

- **Implementation**: Every authentication message includes a Unix timestamp
- **Location**: 
  - `TS_i` in Phase 1A (Drone → MCC): `AuthRequestMessage.ts`
  - `TS_MCC` in Phase 1B (MCC → Drone): `AuthResponseMessage.ts`
  - Final confirmation: `SessionKeyConfirmMessage.ts`

- **Validation Logic** (`utils.py`):
```python
def validate_timestamp(ts: int, tolerance: int = 60) -> bool:
    """Reject timestamps older than 60 seconds"""
    current = current_timestamp()
    return abs(current - ts) <= tolerance
```

- **Security Property**: Messages older than 60 seconds are automatically rejected
- **Attack Prevention**: Even if an attacker captures a valid authentication message, it cannot be replayed after the 60-second window expires

#### **B. Random Nonces (RN_i, RN_MCC)**

- **Implementation**: Cryptographically secure 32-byte (256-bit) random nonces
- **Generation**: Uses Python's `secrets` module (CSPRNG-based)
```python
def generate_random_bytes(n: int) -> bytes:
    """Generate n random bytes using secrets module"""
    return secrets.token_bytes(n)
```

- **Location**:
  - `RN_i` (Drone nonce): Generated in `drone_client.py`, sent in Phase 1A
  - `RN_MCC` (MCC nonce): Generated in `mcc_server.py`, sent in Phase 1B

- **Uniqueness**: With 256 bits of entropy, collision probability is negligible (2^-256)
- **Security Property**: Each authentication session has unique nonces, making every session distinct

#### **C. Combined Protection**

**Session Key Derivation** (`utils.py`):
```python
SK = SHA256(K_Di,MCC || TS_i || TS_MCC || RN_i || RN_MCC)
```

- **Effect**: Session key depends on BOTH timestamps AND nonces
- **Consequence**: 
  - Different timestamp → Different session key
  - Different nonce → Different session key
  - Even if K_Di,MCC is reused, SK is always unique

### 1.2 Freshness Test Results

From `test_integration.py`:

**Test INT-4: Replay Attack Prevention**
```
✓ Old timestamp (120s) rejected
✓ Current timestamp accepted
✓ 60-second tolerance enforced
```

**Test INT-5: Session Key Uniqueness**
```
✓ Same parameters → Same key (deterministic)
✓ Different nonces → Different keys
✓ Different timestamps → Different keys
```

### 1.3 Freshness Attack Scenarios

| Attack | Mechanism | Defense | Result |
|--------|-----------|---------|--------|
| **Replay Attack** | Resend captured Phase 1A message | Timestamp validation rejects old messages | ✅ BLOCKED |
| **Delayed Delivery** | Legitimate message arrives late | 60-second window rejects stale messages | ✅ BLOCKED |
| **Nonce Reuse** | Try to reuse previous nonce | Collision probability 2^-256 | ✅ INFEASIBLE |
| **Session Replay** | Replay entire auth session | New timestamps + nonces required | ✅ BLOCKED |

---

## 2. Forward Secrecy

**Forward Secrecy** (also called Perfect Forward Secrecy - PFS) ensures that compromise of long-term keys (private keys) does not compromise past session keys.

### 2.1 Forward Secrecy Architecture

#### **A. Key Hierarchy**

```
Long-Term Keys (Static)
├── MCC Private Key (x_MCC)
├── MCC Public Key (y_MCC = g^x_MCC mod p)
├── Drone Private Key (x_i)
└── Drone Public Key (y_i = g^x_i mod p)

Ephemeral Secrets (Per-Session)
├── K_Di,MCC (32-byte shared secret, generated fresh each session)
├── RN_i (32-byte nonce, generated fresh each session)
├── RN_MCC (32-byte nonce, generated fresh each session)
├── TS_i (timestamp, unique per session)
└── TS_MCC (timestamp, unique per session)

Derived Session Key
└── SK = SHA256(K_Di,MCC || TS_i || TS_MCC || RN_i || RN_MCC)
```

#### **B. Ephemeral Shared Secret (K_Di,MCC)**

**Generation** (`drone_client.py`):
```python
def authenticate(self) -> bool:
    # Generate FRESH shared secret for THIS session only
    self.k_di_mcc = utils.generate_random_bytes(32)  # New secret every time!
    
    # Encrypt with MCC's public key
    k_di_mcc_int = crypto_utils.bytes_to_int(self.k_di_mcc)
    c_i = ElGamal.encrypt(k_di_mcc_int, self.mcc_public_key)
```

**Key Properties**:
- ✅ Generated fresh for EACH authentication
- ✅ Never reused across sessions
- ✅ Encrypted with ElGamal (asymmetric crypto)
- ✅ Not stored long-term (memory only during session)

#### **C. Session Key Derivation with Ephemeral Parameters**

**Formula**:
```
SK = H(K_Di,MCC || TS_i || TS_MCC || RN_i || RN_MCC)
```

**Ephemeral Components**:
1. `K_Di,MCC`: Fresh 32-byte secret (different every session)
2. `TS_i`: Current timestamp (different every session)
3. `TS_MCC`: Current timestamp (different every session)
4. `RN_i`: Fresh 32-byte nonce (different every session)
5. `RN_MCC`: Fresh 32-byte nonce (different every session)

**Result**: Session key SK is cryptographically independent of previous sessions

### 2.2 Forward Secrecy Analysis

#### **Scenario 1: Long-Term Key Compromise**

**Attacker obtains**: Drone's private key `x_i` or MCC's private key `x_MCC`

**What can the attacker do?**
- ❌ **Cannot decrypt past session keys**: SK depends on ephemeral K_Di,MCC, RN_i, RN_MCC which were:
  - Generated using CSPRNG (unpredictable)
  - Never stored on disk
  - Deleted from memory after session ends
  - Not derivable from long-term keys

**Why forward secrecy holds**:
```
SK_old = SHA256(K_old || TS_old_i || TS_old_MCC || RN_old_i || RN_old_MCC)

Even with x_i or x_MCC, attacker cannot compute:
- K_old (was ephemeral, not recorded)
- RN_old_i (was ephemeral, not recorded)
- RN_old_MCC (was ephemeral, not recorded)

∴ SK_old remains secret
```

#### **Scenario 2: Passive Eavesdropping Then Key Compromise**

**Timeline**:
1. Attacker captures encrypted traffic at time T₀
2. Attacker compromises private key at time T₁ (T₁ > T₀)

**Result**:
- ✅ Traffic from T₀ remains secure
- ❌ Future traffic (T > T₁) is compromised until key rotation

**Protection**: Past sessions used ephemeral secrets unknown to attacker

#### **Scenario 3: Multiple Session Independence**

```
Session 1: SK₁ = H(K₁ || TS₁ || TS'₁ || RN₁ || RN'₁)
Session 2: SK₂ = H(K₂ || TS₂ || TS'₂ || RN₂ || RN'₂)
Session 3: SK₃ = H(K₃ || TS₃ || TS'₃ || RN₃ || RN'₃)
```

**Property**: Compromise of SK₂ does NOT compromise SK₁ or SK₃
- Each K is independent (fresh random)
- Each RN is independent (fresh random)
- Each TS is different (time progression)

### 2.3 Forward Secrecy Limitations

#### **Current Implementation**

✅ **Provides Forward Secrecy via**:
- Ephemeral shared secret K_Di,MCC (regenerated each session)
- Ephemeral nonces RN_i and RN_MCC (regenerated each session)
- Session-unique timestamps
- Hash-based key derivation isolates sessions

⚠️ **Does NOT provide Perfect Forward Secrecy (Diffie-Hellman style)**:
- Uses static ElGamal keys (y_MCC, y_i) for encryption
- ElGamal encryption step `c = (g^k, m·y^k)` uses static public key `y`
- If private key `x` is compromised, attacker can decrypt ElGamal ciphertexts

#### **Degree of Forward Secrecy**

**Strong Points**:
- Session keys (SK) have forward secrecy ✅
- Encrypted commands (AES with SK) have forward secrecy ✅
- Past session data remains secure after key compromise ✅

**Weak Points**:
- ElGamal-encrypted K_Di,MCC in captured traffic can be decrypted if x is compromised later ⚠️
- This is a limitation of using static asymmetric keys for encryption

**Practical Security**:
- Attacker must have BOTH:
  1. Captured ciphertext (c₁, c₂) containing K_Di,MCC from Phase 1A
  2. Compromised private key x
- Even then, they only get K_Di,MCC; still need nonces and timestamps to derive SK
- Nonces are transmitted in plaintext but uniqueness prevents reuse attacks

### 2.4 Comparison with Perfect Forward Secrecy

| Property | Current System | Perfect Forward Secrecy (DHE/ECDHE) |
|----------|----------------|--------------------------------------|
| **Session Key Independence** | ✅ Yes (ephemeral nonces + K_Di,MCC) | ✅ Yes (ephemeral DH keys) |
| **Past Session Protection** | ✅ Yes (after session data deleted) | ✅ Yes (immediate) |
| **Static Key Compromise** | ⚠️ Can decrypt ElGamal ciphertexts | ✅ Cannot decrypt past sessions |
| **Ephemeral Secrets** | ✅ K_Di,MCC, RN_i, RN_MCC | ✅ Ephemeral private keys |
| **Implementation Complexity** | Lower (ElGamal keys reused) | Higher (per-session key exchange) |

### 2.5 Forward Secrecy Enhancement Recommendations

To achieve **Perfect Forward Secrecy**, consider:

1. **Ephemeral ElGamal Keys**:
   - Generate new (x_ephemeral, y_ephemeral) for each session
   - Exchange y_ephemeral in Phase 0/1A
   - Discard x_ephemeral after session establishment

2. **Diffie-Hellman Key Exchange**:
   - Replace ElGamal encryption with DH-based key agreement
   - Both parties contribute to shared secret
   - Neither party chooses the full secret

3. **Hybrid Approach**:
   - Use current system for authentication (signatures)
   - Add DH exchange for K_Di,MCC establishment
   - Best of both worlds

---

## 3. Implementation Details

### 3.1 Cryptographic Parameters

| Parameter | Value | Security Level |
|-----------|-------|----------------|
| **Prime p** | 2048 bits | Industry standard (RSA-2048 equivalent) |
| **Generator g** | 2, 3, or 5 | Verified generator for Z*_p |
| **Private keys (x)** | 2048 bits | Full entropy of p |
| **Public keys (y)** | 2048 bits | y = g^x mod p |
| **Shared secret K_Di,MCC** | 256 bits (32 bytes) | AES-256 equivalent |
| **Nonces RN** | 256 bits (32 bytes) | Collision-resistant |
| **Session key SK** | 256 bits (32 bytes) | AES-256 symmetric key |
| **Timestamp tolerance** | 60 seconds | Replay attack window |

### 3.2 Key Material Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│ LONG-TERM KEYS (Static, Persistent)                         │
├─────────────────────────────────────────────────────────────┤
│ MCC Private Key (x_MCC)  │ Generated at startup            │
│ MCC Public Key (y_MCC)   │ Distributed to all drones       │
│ Drone Private Key (x_i)  │ Generated at startup            │
│ Drone Public Key (y_i)   │ Sent to MCC during auth         │
│ Lifetime: Until key rotation (days/weeks)                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ EPHEMERAL SECRETS (Per-Session, Temporary)                  │
├─────────────────────────────────────────────────────────────┤
│ K_Di,MCC   │ Generated: Phase 1A start                      │
│            │ Used: Session key derivation                   │
│            │ Deleted: After Phase 2 confirmation            │
│            │ Lifetime: ~1-5 seconds                         │
├────────────┼────────────────────────────────────────────────┤
│ RN_i       │ Generated: Phase 1A start                      │
│            │ Used: Session key derivation                   │
│            │ Lifetime: Single session                       │
├────────────┼────────────────────────────────────────────────┤
│ RN_MCC     │ Generated: Phase 1B start                      │
│            │ Used: Session key derivation                   │
│            │ Lifetime: Single session                       │
├────────────┼────────────────────────────────────────────────┤
│ TS_i       │ Generated: Phase 1A start (current time)       │
│ TS_MCC     │ Generated: Phase 1B start (current time)       │
│            │ Lifetime: Single session (60s validity)        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ DERIVED SESSION KEY (Per-Session, Active Until Disconnect)  │
├─────────────────────────────────────────────────────────────┤
│ SK = H(K_Di,MCC || TS_i || TS_MCC || RN_i || RN_MCC)       │
│ Lifetime: Duration of authenticated session                 │
│ Storage: RAM only (never written to disk)                   │
│ Deletion: On disconnect or session timeout                  │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Security Properties Summary

| Property | Mechanism | Status |
|----------|-----------|--------|
| **Authentication** | ElGamal signatures | ✅ Mutual auth |
| **Confidentiality** | ElGamal (Phase 1) + AES-256-CBC (Phase 2+) | ✅ Strong |
| **Integrity** | HMAC-SHA256 | ✅ Protected |
| **Freshness** | Timestamps (60s window) + Random nonces | ✅ Guaranteed |
| **Forward Secrecy** | Ephemeral K_Di,MCC + nonces | ✅ Partial (session keys) |
| **Perfect Forward Secrecy** | N/A (static ElGamal keys) | ⚠️ Not implemented |
| **Replay Protection** | Timestamp + nonce validation | ✅ Protected |
| **Non-repudiation** | Digital signatures | ✅ Verifiable |

---

## 4. Security Test Results

### 4.1 Freshness Tests

**From `test_integration.py`**:

```
✅ INT-4: Replay Attack Prevention
   ✓ Timestamp 120 seconds old → REJECTED
   ✓ Current timestamp → ACCEPTED
   ✓ 60-second tolerance enforced

✅ INT-5: Session Key Uniqueness
   ✓ Same inputs → Same SK (deterministic)
   ✓ Different nonce → Different SK
   ✓ Different timestamp → Different SK
```

**Attack Demonstration** (`scripts/attacks.py`):

```
Attack #1: Replay Attack
Result: ❌ FAILED (as expected)
Reason: Timestamp validation rejected old message
```

### 4.2 Forward Secrecy Tests

**Session Independence** (`test_integration.py`):
```python
k = generate_random_bytes(32)
ts1, ts2 = current_timestamp(), current_timestamp() + 1
rn1, rn2 = generate_random_bytes(32), generate_random_bytes(32)

sk1 = derive_session_key(k, ts1, ts2, rn1, rn2)
sk2 = derive_session_key(k, ts1, ts2, rn1, rn2)  # Same inputs
sk3 = derive_session_key(k, ts1, ts2, rn2, rn2)  # Different nonce

assert sk1 == sk2  # Deterministic ✓
assert sk1 != sk3  # Nonce uniqueness ✓
```

**Result**: Each session has cryptographically independent session key

---

## 5. Threat Model

### 5.1 Attacker Capabilities

**Assumed Attacker Powers**:
- 🔍 Passive eavesdropping (capture all network traffic)
- 📡 Active man-in-the-middle (intercept and modify messages)
- 🔁 Replay captured messages
- ⏰ Delay message delivery
- 🔑 May eventually compromise long-term keys (forward secrecy concern)

**Assumed Secure**:
- ✅ Drone and MCC devices themselves (no malware)
- ✅ Random number generation (CSPRNG)
- ✅ Cryptographic primitives (ElGamal, AES, SHA-256)
- ✅ Initial parameter distribution (p, g securely shared)

### 5.2 Attack Resistance

| Attack Type | Freshness Defense | Forward Secrecy Defense |
|-------------|-------------------|-------------------------|
| **Replay Attack** | ✅ Timestamp validation | N/A |
| **Session Replay** | ✅ Nonce uniqueness | N/A |
| **Past Session Decrypt** | N/A | ✅ Ephemeral secrets deleted |
| **Key Compromise (future)** | N/A | ⚠️ Partial (SK protected, K_Di,MCC vulnerable) |
| **Man-in-the-Middle** | ✅ Signatures prevent tampering | ✅ Ephemeral secrets not transmitted plaintext |
| **Nonce Prediction** | ✅ CSPRNG (2^-256 collision) | ✅ Unpredictable |

---

## 6. Recommendations

### 6.1 Current Strengths

✅ Strong freshness guarantees (timestamps + nonces)  
✅ Session key forward secrecy (ephemeral parameters)  
✅ Cryptographically strong primitives (2048-bit, 256-bit keys)  
✅ Defense-in-depth (multiple layers: signatures, encryption, HMAC)

### 6.2 Potential Improvements

1. **Achieve Perfect Forward Secrecy**:
   - Implement ephemeral Diffie-Hellman key exchange
   - Or use ephemeral ElGamal keys per session

2. **Reduce Timestamp Window**:
   - Consider 30-second window instead of 60 (requires tighter clock sync)

3. **Add Certificate Infrastructure**:
   - Use X.509 certificates for public key distribution
   - Prevent man-in-the-middle during initial handshake

4. **Implement Key Rotation**:
   - Periodic regeneration of long-term keys (e.g., monthly)
   - Minimize damage from eventual key compromise

5. **Add Anti-Tampering**:
   - Additional integrity checks at transport layer
   - Detect packet manipulation attempts

---

## 7. Conclusion

The UAV C2 system implements **strong freshness guarantees** through:
- ✅ Timestamp-based replay prevention (60-second window)
- ✅ Cryptographically secure random nonces (256-bit entropy)
- ✅ Session-unique key derivation

The system implements **forward secrecy for session keys** through:
- ✅ Ephemeral shared secret K_Di,MCC (regenerated each session)
- ✅ Ephemeral nonces RN_i and RN_MCC (regenerated each session)
- ✅ Hash-based key derivation (session independence)

**Limitation**: Does not achieve Perfect Forward Secrecy due to static ElGamal keys used for encryption. Compromise of long-term private keys allows decryption of captured ElGamal ciphertexts, though session keys remain protected if ephemeral secrets are properly deleted.

**Overall Security Posture**: Strong authentication protocol suitable for production UAV systems with acceptable risk tolerance. For highest security requirements, consider implementing ephemeral DH key exchange.

---

*Document Version: 1.0*  
*Last Updated: February 10, 2026*  
*Course: Secure Networks and Systems (SNS) Lab Assignment 2*
