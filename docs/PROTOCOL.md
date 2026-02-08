# PROTOCOL SPECIFICATION

## Message Flow Diagram

```
MCC Server                                    Drone Client
    |                                              |
    |   Phase 0: Parameter Initialization          |
    |<-------------------------------------------->|
    |  M0: {p, g, SL, TS0, ID_MCC}                |
    |--------------------------------------------->|
    |                                         Validate:
    |                                         - p bit_length ≈ SL
    |                                         - SL ≥ 2048
    |                                         - Timestamp valid
    |                                              |
    |   Phase 1A: Authentication Request           |
    |<---------------------------------------------|
    |  {TS_i, RN_i, ID_Di, C_i, Sig_Di}           |
    |  where: C_i = E_KU_MCC(K_Di,MCC)            |
    |          Sig_Di = Sign_KR_Di(...)            |
    |                                              |
    | Verify signature                             |
    | Decrypt C_i → K_Di,MCC                      |
    |                                              |
    |   Phase 1B: Authentication Response          |
    |--------------------------------------------->|
    |  {TS_MCC, RN_MCC, ID_MCC, C_MCC, Sig_MCC}  |
    |  where: C_MCC = E_KU_Di(K_Di,MCC)           |
    |          Sig_MCC = Sign_KR_MCC(...)          |
    |                                         Verify signature
    |                                         Decrypt C_MCC
    |                                              |
    | Derive: SK = H(K||TS_i||TS_MCC||RN_i||RN_MCC)
    |                                         Derive: SK
    |                                              |
    |   Phase 2: Session Key Confirmation          |
    |<---------------------------------------------|
    |  {ID_Di, TS_final, HMAC_SK(ID||TS)}         |
    |                                              |
    | Verify HMAC                                  |
    | Register drone in fleet                      |
    |                                              |
    |   SUCCESS / ERROR                            |
    |--------------------------------------------->|
    |  OPCODE 50 (Success) or 60 (Error)          |
    |                                              |
    |   Phase 3: Group Key Distribution            |
    |   (When broadcast command issued)            |
    |                                              |
    | Generate: GK = H(SK1||SK2||...||KR_MCC)     |
    |                                              |
    |--------------------------------------------->|
    |  {AES_SK(GK), HMAC_SK(...)}                 |
    |                                         Decrypt GK
    |                                         Store GK
    |                                              |
    |   Group Command Broadcast                    |
    |--------------------------------------------->|
    |  {AES_GK(cmd), HMAC_GK(...)}                |
    |                                         Decrypt cmd
    |                                         Execute cmd
    |                                              |
```

---

## OpCodes

| Code | Name | Description |
|------|------|-------------|
| 10 | PARAM_INIT | Parameter initialization (p, g, SL) |
| 20 | AUTH_REQ | Authentication request from drone |
| 30 | AUTH_RES | Authentication response from MCC |
| 40 | SK_CONFIRM | Session key confirmation |
| 50 | SUCCESS | Authentication successful |
| 60 | ERR_MISMATCH | Parameter or authentication error |
| 70 | GROUP_KEY | Group key distribution |
| 80 | GROUP_CMD | Group command broadcast |
| 90 | SHUTDOWN | Shutdown signal |

---

## Message Structures (JSON Format)

### Phase 0: Parameter Initialization

```json
{
  "opcode": 10,
  "p": "large_prime_as_string",
  "g": 2,
  "sl": 2048,
  "ts": 1738876543,
  "id_mcc": "MCC_ROOT"
}
```

### Phase 1A: Authentication Request

```json
{
  "opcode": 20,
  "ts": 1738876544,
  "rn": "hex_encoded_32_byte_nonce",
  "id_drone": "DRONE_001",
  "c1": "elgamal_ciphertext_part1",
  "c2": "elgamal_ciphertext_part2",
  "sig_r": "signature_r_component",
  "sig_s": "signature_s_component"
}
```

### Phase 1B: Authentication Response

```json
{
  "opcode": 30,
  "ts": 1738876545,
  "rn": "hex_encoded_32_byte_nonce",
  "id_mcc": "MCC_ROOT",
  "c1": "elgamal_ciphertext_part1",
  "c2": "elgamal_ciphertext_part2",
  "sig_r": "signature_r_component",
  "sig_s": "signature_s_component"
}
```

### Phase 2: Session Key Confirmation

```json
{
  "opcode": 40,
  "id_drone": "DRONE_001",
  "ts": 1738876546,
  "hmac": "hex_encoded_hmac_tag"
}
```

### Status Message

```json
{
  "opcode": 50,
  "message": "Authentication complete"
}
```

### Phase 3: Group Key Distribution

```json
{
  "opcode": 70,
  "encrypted_gk": "hex_encoded_aes_encrypted_group_key",
  "hmac": "hex_encoded_hmac_tag"
}
```

### Group Command

```json
{
  "opcode": 80,
  "encrypted_cmd": "hex_encoded_aes_encrypted_command",
  "hmac": "hex_encoded_hmac_tag"
}
```

---

## Cryptographic Operations

### ElGamal Key Generation

```
1. Generate prime p (2048+ bits)
2. Find generator g for Z_p*
3. Choose private key x ∈ [1, p-2]
4. Compute public key y = g^x mod p
```

### ElGamal Encryption

```
Given: message m, public key (p, g, y)
1. Choose random k ∈ [1, p-2]
2. Compute c1 = g^k mod p
3. Compute c2 = (m · y^k) mod p
4. Ciphertext: (c1, c2)
```

### ElGamal Decryption

```
Given: ciphertext (c1, c2), private key x
1. Compute s = c1^x mod p
2. Compute s_inv = s^(-1) mod p
3. Recover m = c2 · s_inv mod p
```

### ElGamal Signing

```
Given: message hash H(m), private key (p, g, x)
1. Choose random k where gcd(k, p-1) = 1
2. Compute r = g^k mod p
3. Compute k_inv = k^(-1) mod (p-1)
4. Compute s = (H(m) - x·r) · k_inv mod (p-1)
5. Signature: (r, s)
```

### ElGamal Verification

```
Given: hash H(m), signature (r, s), public key (p, g, y)
1. Check 0 < r < p
2. Compute left = g^H(m) mod p
3. Compute right = y^r · r^s mod p
4. Valid if left ≡ right (mod p)
```

### Session Key Derivation

```
SK = SHA256(K_Di,MCC || TS_i || TS_MCC || RN_i || RN_MCC)

where:
- K_Di,MCC: 32-byte shared secret
- TS_i, TS_MCC: 8-byte timestamps
- RN_i, RN_MCC: 32-byte random nonces
- Result: 32-byte session key
```

### Group Key Aggregation

```
GK = SHA256(SK_1 || SK_2 || ... || SK_n || KR_MCC)

where:
- SK_i: Session keys of all drones
- KR_MCC: MCC's private key (as 32 bytes)
- Result: 32-byte group key
```

---

## Security Properties

### Authentication
- **Mutual**: Both MCC and drone authenticate each other
- **Method**: Digital signatures with ElGamal
- **Freshness**: Timestamps and nonces prevent replay

### Confidentiality
- **Phase 1**: ElGamal encryption (asymmetric)
- **Phase 2+**: AES-256-CBC (symmetric)
- **Key Distribution**: Session keys for individual, group key for fleet

### Integrity
- **Phase 1**: Digital signatures
- **Phase 2+**: HMAC-SHA256

### Forward Secrecy
- Session keys derived from ephemeral nonces
- Group key changes with fleet composition

---

## Implementation Notes

### Thread Safety
- Fleet registry protected by mutex lock
- Each drone handled in separate thread
- No shared mutable state between threads

### Error Handling
- Invalid signatures → connection rejected
- Timestamp out of window → authentication fails
- HMAC mismatch → message rejected
- Network errors → graceful disconnect

### Performance
- Prime generation: ~30-60s (one-time)
- Authentication: ~1-3s per drone
- Command broadcast: <1s for 10 drones

---

**See README.md for complete documentation**
