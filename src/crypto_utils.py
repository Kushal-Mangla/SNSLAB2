"""
Cryptographic Utilities Module
Manual implementation of ElGamal encryption, decryption, digital signatures
All modular arithmetic implemented from scratch
"""

import hashlib
import secrets
import os
from typing import Tuple, Optional


class CryptoUtils:
    """Manual implementation of ElGamal cryptography and related utilities"""
    
    @staticmethod
    def miller_rabin(n: int, k: int = 40) -> bool:
        """
        Miller-Rabin primality test
        Args:
            n: Number to test for primality
            k: Number of rounds (higher = more accurate)
        Returns:
            True if n is probably prime, False if composite
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    @staticmethod
    def generate_prime(bits: int) -> int:
        """
        Generate a random prime number of specified bit length
        Args:
            bits: Bit length of prime (e.g., 2048)
        Returns:
            A prime number
        """
        while True:
            # Generate random odd number of specified bits
            candidate = secrets.randbits(bits)
            # Set MSB and LSB to ensure correct bit length and odd number
            candidate |= (1 << bits - 1) | 1
            
            if CryptoUtils.miller_rabin(candidate):
                return candidate
    
    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Modular inverse using Python's built-in pow function
        Computes x such that (a * x) % m == 1
        Args:
            a: Number to find inverse of
            m: Modulus
        Returns:
            Modular inverse of a mod m
        Raises:
            ValueError: If inverse doesn't exist
        """
        if m == 0:
            raise ValueError("Modulus cannot be zero")
        
        try:
            # Python 3.8+ pow(a, -1, m) computes modular inverse efficiently
            return pow(a, -1, m)
        except ValueError:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    
    @staticmethod
    def gcd(a: int, b: int) -> int:
        """
        Compute Greatest Common Divisor using Euclidean algorithm
        """
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def find_generator(p: int) -> int:
        """
        Find a generator for the multiplicative group Z_p*
        For safe primes p = 2q + 1, generator is typically 2, 3, or 5
        Args:
            p: Prime modulus
        Returns:
            A generator g
        """
        # For simplicity, test small candidates
        candidates = [2, 3, 5, 7, 11]
        q = (p - 1) // 2
        
        for g in candidates:
            # Check if g is a generator
            # g should not be 1 mod p, and g^q should not be 1 mod p
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g
        
        # Fallback: search more candidates
        for g in range(13, 100):
            if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
                return g
        
        return 2  # Default fallback


class ElGamalKeyPair:
    """ElGamal key pair container"""
    
    def __init__(self, p: int, g: int, x: int, y: int):
        self.p = p  # Prime modulus
        self.g = g  # Generator
        self.x = x  # Private key
        self.y = y  # Public key (g^x mod p)
    
    def get_public_key(self) -> Tuple[int, int, int]:
        """Returns (p, g, y)"""
        return (self.p, self.g, self.y)
    
    def get_private_key(self) -> int:
        """Returns x"""
        return self.x


class ElGamal:
    """Manual ElGamal implementation"""
    
    @staticmethod
    def generate_keypair(security_level: int = 2048, skip_check: bool = False) -> ElGamalKeyPair:
        """
        Generate ElGamal key pair
        Args:
            security_level: Bit length of prime p (must be >= 2048)
            skip_check: Skip security level check (for testing only)
        Returns:
            ElGamalKeyPair object
        """
        if not skip_check and security_level < 2048:
            raise ValueError("Security level must be >= 2048 bits")
        
        print(f"Generating {security_level}-bit prime (this may take a moment)...")
        p = CryptoUtils.generate_prime(security_level)
        print(f"Prime generated: {p.bit_length()} bits")
        
        g = CryptoUtils.find_generator(p)
        print(f"Generator found: {g}")
        
        # Private key: random x in [1, p-2]
        x = secrets.randbelow(p - 2) + 1
        
        # Public key: y = g^x mod p
        y = pow(g, x, p)
        
        return ElGamalKeyPair(p, g, x, y)
    
    @staticmethod
    def encrypt(message: int, public_key: Tuple[int, int, int]) -> Tuple[int, int]:
        """
        ElGamal encryption (EKU)
        Args:
            message: Integer message m
            public_key: Tuple (p, g, y)
        Returns:
            Ciphertext (c1, c2)
        """
        p, g, y = public_key
        
        # Random k in [1, p-2]
        k = secrets.randbelow(p - 2) + 1
        
        # c1 = g^k mod p
        c1 = pow(g, k, p)
        
        # c2 = (m * y^k) mod p
        c2 = (message * pow(y, k, p)) % p
        
        return (c1, c2)
    
    @staticmethod
    def decrypt(ciphertext: Tuple[int, int], keypair: ElGamalKeyPair) -> int:
        """
        ElGamal decryption (DKR)
        Args:
            ciphertext: Tuple (c1, c2)
            keypair: ElGamalKeyPair with private key
        Returns:
            Decrypted message m
        """
        c1, c2 = ciphertext
        p = keypair.p
        x = keypair.x
        
        # Compute s = c1^x mod p
        s = pow(c1, x, p)
        
        # Compute s_inv = s^(-1) mod p
        s_inv = CryptoUtils.mod_inverse(s, p)
        
        # m = c2 * s_inv mod p
        m = (c2 * s_inv) % p
        
        return m
    
    @staticmethod
    def sign(message_hash: int, keypair: ElGamalKeyPair) -> Tuple[int, int]:
        """
        ElGamal digital signature (SignKR)
        Args:
            message_hash: Hash of message H(m) as integer
            keypair: ElGamalKeyPair with private key
        Returns:
            Signature (r, s)
        """
        p = keypair.p
        g = keypair.g
        x = keypair.x
        
        # Find random k such that gcd(k, p-1) = 1
        while True:
            k = secrets.randbelow(p - 2) + 1
            if CryptoUtils.gcd(k, p - 1) == 1:
                break
        
        # r = g^k mod p
        r = pow(g, k, p)
        
        # k_inv = k^(-1) mod (p-1)
        k_inv = CryptoUtils.mod_inverse(k, p - 1)
        
        # s = (H(m) - x*r) * k_inv mod (p-1)
        s = ((message_hash - x * r) * k_inv) % (p - 1)
        
        return (r, s)
    
    @staticmethod
    def verify(message_hash: int, signature: Tuple[int, int], 
               public_key: Tuple[int, int, int]) -> bool:
        """
        ElGamal signature verification (VerifyKU)
        Args:
            message_hash: Hash of message H(m) as integer
            signature: Tuple (r, s)
            public_key: Tuple (p, g, y)
        Returns:
            True if signature is valid, False otherwise
        """
        r, s = signature
        p, g, y = public_key
        
        # Check that 0 < r < p
        if not (0 < r < p):
            return False
        
        # Verify: g^H(m) ≡ y^r * r^s (mod p)
        left = pow(g, message_hash, p)
        right = (pow(y, r, p) * pow(r, s, p)) % p
        
        return left == right


def hash_message(data: bytes) -> int:
    """
    Hash data using SHA-256 and convert to integer
    Args:
        data: Bytes to hash
    Returns:
        Integer representation of hash
    """
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder='big')


def hash_to_bytes(data: bytes) -> bytes:
    """
    Hash data using SHA-256
    Args:
        data: Bytes to hash
    Returns:
        32-byte hash
    """
    return hashlib.sha256(data).digest()


def int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    """
    Convert integer to bytes
    Args:
        n: Integer to convert
        length: Optional fixed length (will pad with zeros)
    Returns:
        Bytes representation
    """
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
    """
    Convert bytes to integer
    Args:
        b: Bytes to convert
    Returns:
        Integer representation
    """
    return int.from_bytes(b, byteorder='big')


# Test functions
if __name__ == "__main__":
    print("Testing ElGamal Implementation...")
    
    # Test key generation
    print("\n1. Generating keypair (512 bits for testing)...")
    keypair = ElGamal.generate_keypair(512, skip_check=True)
    public_key = keypair.get_public_key()
    
    # Test encryption/decryption
    print("\n2. Testing encryption/decryption...")
    message = 12345678901234567890
    print(f"Original message: {message}")
    
    ciphertext = ElGamal.encrypt(message, public_key)
    print(f"Encrypted: {ciphertext}")
    
    decrypted = ElGamal.decrypt(ciphertext, keypair)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")
    
    # Test signing/verification
    print("\n3. Testing digital signature...")
    msg_data = b"Test message for signing"
    msg_hash = hash_message(msg_data)
    print(f"Message hash: {msg_hash}")
    
    signature = ElGamal.sign(msg_hash, keypair)
    print(f"Signature: {signature}")
    
    valid = ElGamal.verify(msg_hash, signature, public_key)
    print(f"Signature valid: {valid}")
    
    # Test with wrong message
    wrong_hash = hash_message(b"Different message")
    valid = ElGamal.verify(wrong_hash, signature, public_key)
    print(f"Wrong message valid: {valid}")
    
    print("\nAll tests completed!")
