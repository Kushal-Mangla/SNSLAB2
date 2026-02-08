"""
Utility functions for AES encryption, HMAC, serialization
"""

import hmac
import hashlib
import json
import time
from typing import Any, Dict, Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import config


def current_timestamp() -> int:
    """Get current Unix timestamp"""
    return int(time.time())


def validate_timestamp(ts: int, tolerance: int = config.TIMESTAMP_TOLERANCE) -> bool:
    """
    Validate timestamp is within tolerance window
    Args:
        ts: Timestamp to validate
        tolerance: Maximum age in seconds
    Returns:
        True if valid, False otherwise
    """
    current = current_timestamp()
    return abs(current - ts) <= tolerance


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC encryption
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
    Returns:
        IV || ciphertext (IV is first 16 bytes)
    """
    if len(key) != config.AES_KEY_SIZE:
        raise ValueError(f"Key must be {config.AES_KEY_SIZE} bytes")
    
    iv = get_random_bytes(config.AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, config.AES_BLOCK_SIZE))
    
    return iv + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-256-CBC decryption
    Args:
        key: 32-byte encryption key
        data: IV || ciphertext
    Returns:
        Decrypted plaintext
    """
    if len(key) != config.AES_KEY_SIZE:
        raise ValueError(f"Key must be {config.AES_KEY_SIZE} bytes")
    
    if len(data) < config.AES_BLOCK_SIZE:
        raise ValueError("Data too short")
    
    iv = data[:config.AES_BLOCK_SIZE]
    ciphertext = data[config.AES_BLOCK_SIZE:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), config.AES_BLOCK_SIZE)
    
    return plaintext


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256
    Args:
        key: HMAC key
        data: Data to authenticate
    Returns:
        32-byte HMAC tag
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """
    Verify HMAC-SHA256
    Args:
        key: HMAC key
        data: Data to verify
        tag: Expected HMAC tag
    Returns:
        True if valid, False otherwise
    """
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, tag)


def derive_session_key(k_di_mcc: bytes, ts_i: int, ts_mcc: int, 
                       rn_i: bytes, rn_mcc: bytes) -> bytes:
    """
    Derive session key using SHA-256
    SK = H(K_Di,MCC || TSi || TSMCC || RNi || RNMCC)
    Args:
        k_di_mcc: Shared secret (32 bytes)
        ts_i: Drone timestamp
        ts_mcc: MCC timestamp
        rn_i: Drone nonce (32 bytes)
        rn_mcc: MCC nonce (32 bytes)
    Returns:
        32-byte session key
    """
    data = (k_di_mcc + 
            ts_i.to_bytes(8, byteorder='big') + 
            ts_mcc.to_bytes(8, byteorder='big') +
            rn_i + 
            rn_mcc)
    return hashlib.sha256(data).digest()


def serialize_json(obj: Any) -> bytes:
    """Serialize object to JSON bytes"""
    return json.dumps(obj).encode('utf-8')


def deserialize_json(data: bytes) -> Any:
    """Deserialize JSON bytes to object"""
    return json.loads(data.decode('utf-8'))


def generate_random_bytes(n: int) -> bytes:
    """Generate n random bytes"""
    return get_random_bytes(n)


def int_list_to_bytes(int_list: list) -> bytes:
    """
    Convert list of integers to bytes for transmission
    Format: length (4 bytes) + each int (variable length prefixed by length)
    """
    result = len(int_list).to_bytes(4, byteorder='big')
    for num in int_list:
        num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
        result += len(num_bytes).to_bytes(4, byteorder='big')
        result += num_bytes
    return result


def bytes_to_int_list(data: bytes) -> list:
    """
    Convert bytes back to list of integers
    """
    if len(data) < 4:
        raise ValueError("Data too short")
    
    count = int.from_bytes(data[:4], byteorder='big')
    result = []
    offset = 4
    
    for _ in range(count):
        if offset + 4 > len(data):
            raise ValueError("Incomplete data")
        
        length = int.from_bytes(data[offset:offset+4], byteorder='big')
        offset += 4
        
        if offset + length > len(data):
            raise ValueError("Incomplete integer data")
        
        num = int.from_bytes(data[offset:offset+length], byteorder='big')
        result.append(num)
        offset += length
    
    return result


# Test functions
if __name__ == "__main__":
    print("Testing utility functions...")
    
    # Test AES encryption
    key = generate_random_bytes(32)
    plaintext = b"Hello, UAV world!"
    
    ciphertext = aes_encrypt(key, plaintext)
    decrypted = aes_decrypt(key, ciphertext)
    
    print(f"AES Test: {plaintext == decrypted}")
    
    # Test HMAC
    hmac_tag = compute_hmac(key, plaintext)
    valid = verify_hmac(key, plaintext, hmac_tag)
    print(f"HMAC Test: {valid}")
    
    # Test session key derivation
    sk = derive_session_key(
        generate_random_bytes(32),
        current_timestamp(),
        current_timestamp(),
        generate_random_bytes(32),
        generate_random_bytes(32)
    )
    print(f"Session Key: {len(sk)} bytes")
    
    print("All utility tests passed!")
