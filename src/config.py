"""
Configuration and Constants for UAV C2 System
"""

# Security parameters
SECURITY_LEVEL = 2048  # Minimum 2048 bits for prime p
DRONE_MIN_SECURITY_LEVEL = 2048  # Drone's internal safety threshold

# Network parameters
MCC_HOST = "127.0.0.1"
MCC_PORT = 9999

# Protocol opcodes
class OpCode:
    PARAM_INIT = 10      # Parameter initialization
    AUTH_REQ = 20        # Authentication request
    AUTH_RES = 30        # Authentication response
    SK_CONFIRM = 40      # Session key confirmation
    SUCCESS = 50         # Success
    ERR_MISMATCH = 60    # Error: parameter mismatch
    GROUP_KEY = 70       # Group key distribution
    GROUP_CMD = 80       # Group command broadcast
    ACK = 85             # Acknowledgment
    SHUTDOWN = 90        # Shutdown signal

# Timeouts and limits
CONNECTION_TIMEOUT = 30  # seconds
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB
TIMESTAMP_TOLERANCE = 60  # seconds - tolerance for timestamp validation

# IDs
MCC_ID = "MCC_ROOT"

# AES parameters
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16  # 128 bits

# Message separators
FIELD_SEPARATOR = b"||"
COMPONENT_SEPARATOR = b"::"
