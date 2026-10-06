import hashlib
import hmac
import secrets
from pathlib import Path


def calculate_file_hash(file_path: str | Path) -> str:
    """Computes SHA-256 checksum of a file (simulating PCR measurement)."""
    hasher = hashlib.sha256()
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found at: {file_path}")
    
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_data_hash(data: str | bytes) -> str:
    """Computes SHA-256 checksum of string or byte buffer."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_nonce(num_bytes: int = 16) -> str:
    """Generates a cryptographically strong pseudo-random challenge nonce."""
    return secrets.token_hex(num_bytes)


def build_canonical_attestation_string(device_id: str, nonce: str, firmware_hash: str, timestamp: int) -> str:
    """
    Builds the standardized canonical string that both device and verifier sign/verify.
    Format: {device_id}|{nonce}|{firmware_hash}|{timestamp}
    """
    return f"{device_id}|{nonce}|{firmware_hash}|{timestamp}"


def generate_hmac_signature(secret_key: str, message: str) -> str:
    """Generates HMAC-SHA256 signature using the device's shared secret key."""
    key_bytes = secret_key.encode("utf-8")
    msg_bytes = message.encode("utf-8")
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()


def verify_hmac_signature(secret_key: str, message: str, signature: str) -> bool:
    """
    Safely verifies the HMAC-SHA256 signature against timing attacks.
    """
    expected_sig = generate_hmac_signature(secret_key, message)
    return hmac.compare_digest(expected_sig, signature)
