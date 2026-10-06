import secrets
import time
from typing import Optional, Tuple
from .crypto_utils import (
    build_canonical_attestation_string,
    generate_hmac_signature,
    generate_nonce,
    verify_hmac_signature,
)
from .database import get_db_connection
from .models import AttestationDiagnostics, AttestationRequest, AttestationResponse

NONCE_EXPIRY_SECONDS = 60
TOKEN_VALIDITY_SECONDS = 300  # Trust token valid for 5 minutes before re-attestation is required


class AttestationEngine:
    @staticmethod
    def issue_challenge(device_id: str) -> Tuple[str, int]:
        """Issues an anti-replay nonce tied to the device."""
        conn = get_db_connection()
        cursor = conn.cursor()

        nonce = generate_nonce(16)
        now = time.time()
        expires_at = now + NONCE_EXPIRY_SECONDS

        cursor.execute("""
            INSERT INTO challenges (nonce, device_id, created_at, expires_at, is_used)
            VALUES (?, ?, ?, ?, 0)
        """, (nonce, device_id, now, expires_at))
        conn.commit()
        conn.close()

        return nonce, NONCE_EXPIRY_SECONDS

    @staticmethod
    def verify_device(req: AttestationRequest) -> AttestationResponse:
        """
        Executes policy verification:
        1. Registration / Identity check
        2. Nonce freshness and anti-replay verification
        3. HMAC signature cryptographic validation
        4. Integrity measurement matching against Golden Baseline
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        now = time.time()

        # Default diagnostics state
        diag = AttestationDiagnostics(
            reported_hash=req.firmware_hash,
            expected_hash=None,
            signature_valid=False,
            nonce_valid=False,
            integrity_valid=False
        )

        def log_and_respond(status: str, allowed: bool, reason: str, token: Optional[str] = None, expires_in: Optional[int] = None):
            cursor.execute("""
                INSERT INTO attestation_logs (
                    device_id, timestamp, nonce, reported_hash, expected_hash,
                    trust_status, reason, is_allowed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (req.device_id, now, req.nonce, req.firmware_hash, diag.expected_hash, status, reason, 1 if allowed else 0))

            if not allowed:
                # Revoke trust status and token if untrusted
                cursor.execute("""
                    UPDATE devices
                    SET trust_status = 'UNTRUSTED', trust_token = NULL, token_expires_at = NULL, last_attested_at = ?
                    WHERE device_id = ?
                """, (now, req.device_id))
            else:
                cursor.execute("""
                    UPDATE devices
                    SET trust_status = 'TRUSTED', trust_token = ?, token_expires_at = ?, last_attested_at = ?
                    WHERE device_id = ?
                """, (token, now + (expires_in or 0), now, req.device_id))

            conn.commit()
            conn.close()

            return AttestationResponse(
                device_id=req.device_id,
                trust_status=status,
                is_allowed=allowed,
                trust_token=token,
                token_expires_in=expires_in,
                reason=reason,
                diagnostics=diag
            )

        # 1. Check if device exists in DB
        cursor.execute("SELECT * FROM devices WHERE device_id = ?", (req.device_id,))
        device = cursor.fetchone()
        if not device:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason=f"Identity Check Failed: Device '{req.device_id}' is not registered in the system."
            )

        secret_key = device["secret_key"]
        golden_hash = device["golden_hash"]
        diag.expected_hash = golden_hash

        # 2. Verify Challenge Nonce (Freshness & Anti-Replay)
        cursor.execute("SELECT * FROM challenges WHERE nonce = ?", (req.nonce,))
        challenge = cursor.fetchone()

        if not challenge:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason="Challenge Verification Failed: Nonce not found or never issued."
            )

        if challenge["device_id"] != req.device_id:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason="Spoofing Attempt Detected: Nonce was issued to a different device."
            )

        if challenge["is_used"] == 1:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason="Replay Attack Detected: Nonce has already been consumed."
            )

        if now > challenge["expires_at"]:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason="Challenge Expired: Nonce timed out before attestation quote was submitted."
            )

        # Mark nonce as consumed
        cursor.execute("UPDATE challenges SET is_used = 1 WHERE nonce = ?", (req.nonce,))
        diag.nonce_valid = True

        # 3. Authenticity / Cryptographic Signature Verification
        canonical_msg = build_canonical_attestation_string(
            req.device_id, req.nonce, req.firmware_hash, req.timestamp
        )
        is_sig_valid = verify_hmac_signature(secret_key, canonical_msg, req.signature)
        diag.signature_valid = is_sig_valid

        if not is_sig_valid:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason="Authentication Failed: Invalid cryptographic signature or secret key mismatch."
            )

        # 4. Integrity Measurement Verification (Remote Attestation)
        is_integrity_valid = (req.firmware_hash.lower() == golden_hash.lower())
        diag.integrity_valid = is_integrity_valid

        if not is_integrity_valid:
            return log_and_respond(
                status="UNTRUSTED",
                allowed=False,
                reason=f"Integrity Violation: Firmware hash mismatch. Possible tampering or unauthorized modification detected."
            )

        # All checks passed successfully! Device is TRUSTED
        trust_token = f"TRUST_TOKEN_{secrets.token_urlsafe(24)}"
        return log_and_respond(
            status="TRUSTED",
            allowed=True,
            reason="Device verified successfully. Identity, freshness, authenticity, and firmware integrity are all valid.",
            token=trust_token,
            expires_in=TOKEN_VALIDITY_SECONDS
        )

    @staticmethod
    def verify_telemetry_access(device_id: str, trust_token: str) -> Tuple[bool, str]:
        """
        Gatekeeper function: Inspects whether the calling device is currently TRUSTED
        and holds an active, unexpired trust token.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        now = time.time()

        cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        device = cursor.fetchone()
        conn.close()

        if not device:
            return False, f"Device '{device_id}' not found."

        if device["trust_status"] != "TRUSTED":
            return False, f"Access Denied: Device '{device_id}' is marked as UNTRUSTED. Must complete attestation first."

        if not device["trust_token"] or device["trust_token"] != trust_token:
            return False, "Access Denied: Invalid or revoked trust token."

        if device["token_expires_at"] and now > device["token_expires_at"]:
            return False, "Access Denied: Trust token has expired. Re-attestation required."

        return True, "Access Granted"
