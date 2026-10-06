from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ChallengeRequest(BaseModel):
    device_id: str = Field(..., example="IOT-DEV-101", description="Unique device ID requesting an attestation challenge")


class ChallengeResponse(BaseModel):
    device_id: str
    nonce: str = Field(..., description="Cryptographic single-use nonce for remote attestation")
    expires_in_seconds: int = Field(60, description="Validity period of the challenge in seconds")


class AttestationRequest(BaseModel):
    device_id: str = Field(..., example="IOT-DEV-101")
    nonce: str = Field(..., description="Challenge nonce received from the verifier")
    firmware_hash: str = Field(..., description="SHA-256 measurement of the active firmware/boot configuration")
    timestamp: int = Field(..., description="Unix timestamp of the measurement")
    signature: str = Field(..., description="HMAC-SHA256 signature calculated over (device_id|nonce|firmware_hash|timestamp)")


class AttestationDiagnostics(BaseModel):
    reported_hash: str
    expected_hash: Optional[str] = None
    signature_valid: bool
    nonce_valid: bool
    integrity_valid: bool


class AttestationResponse(BaseModel):
    device_id: str
    trust_status: str = Field(..., description="'TRUSTED' or 'UNTRUSTED'")
    is_allowed: bool = Field(..., description="Whether network gatekeeper grants access")
    trust_token: Optional[str] = Field(None, description="Temporary access token if trusted")
    token_expires_in: Optional[int] = Field(None, description="Token TTL in seconds")
    reason: str = Field(..., description="Detailed explanation of the trust verdict")
    diagnostics: Optional[AttestationDiagnostics] = None


class TelemetryRequest(BaseModel):
    device_id: str = Field(..., example="IOT-DEV-101")
    trust_token: str = Field(..., description="Current valid trust token obtained via successful attestation")
    payload: Dict[str, Any] = Field(..., example={"temperature": 24.5, "pressure": 1013.2})


class DeviceRegistrationRequest(BaseModel):
    device_id: str = Field(..., example="IOT-DEV-200")
    device_name: str = Field(..., example="Water Pump Sensor")
    secret_key: str = Field(..., example="SECRET_KEY_CUSTOM_200")
    golden_hash: str = Field(..., description="Verified SHA-256 baseline hash of the authentic firmware")
