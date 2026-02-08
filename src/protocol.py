"""
Protocol message structures and serialization
Handles all message formats for the UAV C2 protocol
"""

import json
from typing import Dict, Any, Tuple, Optional
from config import OpCode
import crypto_utils


class Message:
    """Base class for protocol messages"""
    
    def __init__(self, opcode: int):
        self.opcode = opcode
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes"""
        raise NotImplementedError
    
    @staticmethod
    def from_bytes(data: bytes) -> 'Message':
        """Deserialize message from bytes"""
        raise NotImplementedError


class ParameterInitMessage:
    """Phase 0: Parameter Initialization (MCC → Drone)"""
    
    def __init__(self, p: int, g: int, sl: int, ts: int, id_mcc: str, y_mcc: int = None):
        self.opcode = OpCode.PARAM_INIT
        self.p = p          # Prime modulus
        self.g = g          # Generator
        self.sl = sl        # Security level
        self.ts = ts        # Timestamp
        self.id_mcc = id_mcc  # MCC identifier
        self.y_mcc = y_mcc  # MCC public key
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'p': str(self.p),  # Convert to string to handle large numbers
            'g': self.g,
            'sl': self.sl,
            'ts': self.ts,
            'id_mcc': self.id_mcc,
            'y_mcc': str(self.y_mcc) if self.y_mcc else None
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'ParameterInitMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return ParameterInitMessage(
            int(obj['p']),
            obj['g'],
            obj['sl'],
            obj['ts'],
            obj['id_mcc'],
            int(obj['y_mcc']) if obj.get('y_mcc') else None
        )


class AuthRequestMessage:
    """Phase 1A: Drone → MCC (Authentication Request)"""
    
    def __init__(self, ts: int, rn: bytes, id_drone: str, 
                 ciphertext: Tuple[int, int], signature: Tuple[int, int], y_drone: int = None):
        self.opcode = OpCode.AUTH_REQ
        self.ts = ts              # Timestamp
        self.rn = rn              # Random nonce (32 bytes)
        self.id_drone = id_drone  # Drone identifier
        self.ciphertext = ciphertext  # (c1, c2) - ElGamal encrypted K_Di,MCC
        self.signature = signature    # (r, s) - Digital signature
        self.y_drone = y_drone    # Drone's public key
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'ts': self.ts,
            'rn': self.rn.hex(),  # Convert bytes to hex string
            'id_drone': self.id_drone,
            'c1': str(self.ciphertext[0]),
            'c2': str(self.ciphertext[1]),
            'sig_r': str(self.signature[0]),
            'sig_s': str(self.signature[1]),
            'y_drone': str(self.y_drone) if self.y_drone else None
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'AuthRequestMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return AuthRequestMessage(
            obj['ts'],
            bytes.fromhex(obj['rn']),
            obj['id_drone'],
            (int(obj['c1']), int(obj['c2'])),
            (int(obj['sig_r']), int(obj['sig_s'])),
            int(obj['y_drone']) if obj.get('y_drone') else None
        )


class AuthResponseMessage:
    """Phase 1B: MCC → Drone (Authentication Response)"""
    
    def __init__(self, ts: int, rn: bytes, id_mcc: str,
                 ciphertext: Tuple[int, int], signature: Tuple[int, int]):
        self.opcode = OpCode.AUTH_RES
        self.ts = ts          # Timestamp
        self.rn = rn          # Random nonce (32 bytes)
        self.id_mcc = id_mcc  # MCC identifier
        self.ciphertext = ciphertext  # (c1, c2) - ElGamal encrypted K_Di,MCC
        self.signature = signature    # (r, s) - Digital signature
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'ts': self.ts,
            'rn': self.rn.hex(),
            'id_mcc': self.id_mcc,
            'c1': str(self.ciphertext[0]),
            'c2': str(self.ciphertext[1]),
            'sig_r': str(self.signature[0]),
            'sig_s': str(self.signature[1])
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'AuthResponseMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return AuthResponseMessage(
            obj['ts'],
            bytes.fromhex(obj['rn']),
            obj['id_mcc'],
            (int(obj['c1']), int(obj['c2'])),
            (int(obj['sig_r']), int(obj['sig_s']))
        )


class SessionKeyConfirmMessage:
    """Phase 2: Session Key Confirmation"""
    
    def __init__(self, id_drone: str, ts: int, hmac_tag: bytes):
        self.opcode = OpCode.SK_CONFIRM
        self.id_drone = id_drone
        self.ts = ts
        self.hmac_tag = hmac_tag  # HMAC_SK(ID_Di || TS_final)
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'id_drone': self.id_drone,
            'ts': self.ts,
            'hmac': self.hmac_tag.hex()
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'SessionKeyConfirmMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return SessionKeyConfirmMessage(
            obj['id_drone'],
            obj['ts'],
            bytes.fromhex(obj['hmac'])
        )


class StatusMessage:
    """Status messages (SUCCESS, ERR_MISMATCH)"""
    
    def __init__(self, opcode: int, message: str = ""):
        self.opcode = opcode
        self.message = message
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'message': self.message
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'StatusMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return StatusMessage(obj['opcode'], obj.get('message', ''))


class GroupKeyMessage:
    """Phase 3: Group Key Distribution"""
    
    def __init__(self, encrypted_gk: bytes, hmac_tag: bytes):
        self.opcode = OpCode.GROUP_KEY
        self.encrypted_gk = encrypted_gk  # AES-encrypted group key
        self.hmac_tag = hmac_tag          # HMAC for integrity
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'encrypted_gk': self.encrypted_gk.hex(),
            'hmac': self.hmac_tag.hex()
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'GroupKeyMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return GroupKeyMessage(
            bytes.fromhex(obj['encrypted_gk']),
            bytes.fromhex(obj['hmac'])
        )


class GroupCommandMessage:
    """Group command broadcast"""
    
    def __init__(self, encrypted_cmd: bytes, hmac_tag: bytes):
        self.opcode = OpCode.GROUP_CMD
        self.encrypted_cmd = encrypted_cmd  # AES-encrypted command
        self.hmac_tag = hmac_tag            # HMAC for integrity
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {
            'opcode': self.opcode,
            'encrypted_cmd': self.encrypted_cmd.hex(),
            'hmac': self.hmac_tag.hex()
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'GroupCommandMessage':
        """Deserialize from bytes"""
        obj = json.loads(data.decode('utf-8'))
        return GroupCommandMessage(
            bytes.fromhex(obj['encrypted_cmd']),
            bytes.fromhex(obj['hmac'])
        )


class ShutdownMessage:
    """Shutdown signal"""
    
    def __init__(self):
        self.opcode = OpCode.SHUTDOWN
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        data = {'opcode': self.opcode}
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'ShutdownMessage':
        """Deserialize from bytes"""
        return ShutdownMessage()


def send_message(sock, message: Message) -> None:
    """
    Send a message over socket
    Format: 4-byte length prefix + message data
    """
    data = message.to_bytes()
    length = len(data)
    sock.sendall(length.to_bytes(4, byteorder='big') + data)


def receive_message(sock) -> Optional[Dict[str, Any]]:
    """
    Receive a message from socket
    Returns parsed JSON dict or None on error
    """
    # Read 4-byte length prefix
    length_data = sock.recv(4)
    if len(length_data) < 4:
        return None
    
    length = int.from_bytes(length_data, byteorder='big')
    
    # Read message data
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), 4096))
        if not chunk:
            return None
        data += chunk
    
    # Parse JSON
    try:
        return json.loads(data.decode('utf-8'))
    except:
        return None


def get_opcode(msg: Dict[str, Any]) -> int:
    """Extract opcode from message dict"""
    return msg.get('opcode', -1)
