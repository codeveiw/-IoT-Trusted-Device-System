import time
from contextlib import asynccontextmanager
from typing import Optional
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

from .database import get_db_connection, init_db
from .models import (
    AttestationRequest,
    AttestationResponse,
    ChallengeRequest,
    ChallengeResponse,
    DeviceRegistrationRequest,
    TelemetryRequest,
)
from .verifier import AttestationEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database on startup
    init_db()
    yield


app = FastAPI(
    title="IoT Trusted Device Verification Server",
    description="Remote Attestation and Policy Gatekeeper engine simulating Trusted Computing principles for IoT.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for dashboard and external frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


DASHBOARD_PATH = Path(__file__).resolve().parent.parent / "templates" / "dashboard.html"


@app.get("/")
def read_root():
    return {
        "system": "IoT Trusted Device System",
        "description": "Trusted Computing Attestation Server & Zero-Trust Gatekeeper",
        "status": "online",
        "docs_url": "/docs",
        "dashboard_url": "/dashboard",
    }


@app.get("/dashboard", response_class=HTMLResponse, summary="Interactive Web Dashboard")
def get_dashboard():
    if not DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard template not found.")
    return FileResponse(DASHBOARD_PATH)


# ==========================================
# 1. ATTESTATION & CHALLENGE ENDPOINTS
# ==========================================

@app.post("/api/challenge", response_model=ChallengeResponse, summary="1. Request Attestation Challenge Nonce")
def request_challenge(req: ChallengeRequest):
    """
    Step 1 in Remote Attestation:
    The device requests a challenge nonce to guarantee freshness and prevent replay attacks.
    """
    nonce, expiry = AttestationEngine.issue_challenge(req.device_id)
    return ChallengeResponse(
        device_id=req.device_id,
        nonce=nonce,
        expires_in_seconds=expiry,
    )


@app.post("/api/attest", response_model=AttestationResponse, summary="2. Submit Attestation Quote for Verification")
def submit_attestation(req: AttestationRequest):
    """
    Step 2 in Remote Attestation:
    Device submits its firmware measurement hash, challenge nonce, timestamp, and HMAC signature.
    The server evaluates identity, authenticity, freshness, and integrity.
    """
    verdict = AttestationEngine.verify_device(req)
    return verdict


# ==========================================
# 2. ZERO-TRUST GATEKEEPER SERVICE
# ==========================================

@app.post("/api/telemetry", summary="3. Protected IoT Service (Data Ingestion)")
def submit_telemetry(req: TelemetryRequest):
    """
    Access Control Gatekeeper:
    Only devices currently marked as TRUSTED with a valid Trust Token can submit telemetry.
    Untrusted or tampered devices are rejected with 403 Forbidden.
    """
    is_allowed, reason = AttestationEngine.verify_telemetry_access(req.device_id, req.trust_token)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO telemetry_logs (device_id, payload, timestamp, accepted, rejection_reason)
        VALUES (?, ?, ?, ?, ?)
    """, (req.device_id, str(req.payload), time.time(), 1 if is_allowed else 0, reason if not is_allowed else None))
    conn.commit()
    conn.close()

    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "status": "UNTRUSTED_REJECTED",
                "device_id": req.device_id,
                "reason": reason
            }
        )

    return {
        "status": "ACCEPTED",
        "device_id": req.device_id,
        "message": "Telemetry received and verified successfully.",
        "received_data": req.payload
    }


# ==========================================
# 3. MANAGEMENT & MONITORING ENDPOINTS
# ==========================================

@app.get("/api/devices", summary="List All Registered Devices")
def list_devices():
    """Returns all registered devices and their current trust states."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT device_id, device_name, golden_hash, trust_status, 
               token_expires_at, last_attested_at, created_at 
        FROM devices
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    devices = [dict(row) for row in rows]
    return {"total": len(devices), "devices": devices}


@app.post("/api/devices", summary="Register a New Device")
def register_device(req: DeviceRegistrationRequest):
    """Registers a new trusted device with its expected Golden Measurement."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = time.time()

    try:
        cursor.execute("""
            INSERT INTO devices (
                device_id, device_name, secret_key, golden_hash,
                trust_status, created_at
            ) VALUES (?, ?, ?, ?, 'UNTRUSTED', ?)
        """, (req.device_id, req.device_name, req.secret_key, req.golden_hash, now))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Failed to register device: {str(e)}")

    conn.close()
    return {"message": f"Device '{req.device_id}' registered successfully."}


@app.post("/api/devices/{device_id}/revoke", summary="Manually Revoke Trust")
def revoke_device_trust(device_id: str):
    """Instantly revokes a device's trust status (manual quarantine)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE devices
        SET trust_status = 'UNTRUSTED', trust_token = NULL, token_expires_at = NULL
        WHERE device_id = ?
    """, (device_id,))
    conn.commit()
    conn.close()
    return {"message": f"Trust status for '{device_id}' has been revoked."}


@app.get("/api/logs", summary="Get Attestation Audit Logs")
def get_attestation_logs(limit: int = 50):
    """Retrieves chronological verification audit logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM attestation_logs
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return {"logs": [dict(row) for row in rows]}


@app.get("/api/stats", summary="Get System Trust Statistics")
def get_stats():
    """Summary statistics for the dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM devices")
    total_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM devices WHERE trust_status = 'TRUSTED'")
    trusted_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM devices WHERE trust_status = 'UNTRUSTED'")
    untrusted_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM attestation_logs WHERE is_allowed = 0")
    total_violations = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM telemetry_logs WHERE accepted = 1")
    telemetry_accepted = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM telemetry_logs WHERE accepted = 0")
    telemetry_blocked = cursor.fetchone()[0]

    conn.close()
    return {
        "total_devices": total_devices,
        "trusted_devices": trusted_devices,
        "untrusted_devices": untrusted_devices,
        "total_violations": total_violations,
        "telemetry_accepted": telemetry_accepted,
        "telemetry_blocked": telemetry_blocked
    }


# ==========================================
# 4. INTERACTIVE SIMULATION ENGINE
# ==========================================

@app.post("/api/simulate/run/{scenario_id}", summary="Run Simulation Scenario")
def run_simulation_scenario(scenario_id: int):
    """
    Executes a simulation scenario directly:
    1 = Legitimate Device (Authentic firmware & valid key -> TRUSTED)
    2 = Tampered Firmware (Injected backdoor -> UNTRUSTED)
    3 = Rogue Secret Key (Forged key / auth failure -> UNTRUSTED)
    4 = Replay Attack (Reusing consumed nonce -> UNTRUSTED)
    """
    from .crypto_utils import calculate_file_hash, build_canonical_attestation_string, generate_hmac_signature

    firmware_dir = Path(__file__).resolve().parent.parent / "simulator" / "firmware_samples"
    genuine_fw = firmware_dir / "firmware_v1.bin"
    tampered_fw = firmware_dir / "firmware_tampered.bin"

    logs = []

    if scenario_id == 1:
        dev_id = "IOT-DEV-101"
        secret_key = "SECRET_KEY_101_SECURE"
        fw_path = genuine_fw
        logs.append(f"▶️ [Scenario 1] Running Legitimate Device ({dev_id})")
        nonce, _ = AttestationEngine.issue_challenge(dev_id)
        logs.append(f"🌐 [Challenge] Nonce issued: {nonce}")
        fw_hash = calculate_file_hash(fw_path)
        logs.append(f"🔍 [Measured Boot] SHA-256: {fw_hash[:16]}...{fw_hash[-16:]}")
        ts = int(time.time())
        msg = build_canonical_attestation_string(dev_id, nonce, fw_hash, ts)
        sig = generate_hmac_signature(secret_key, msg)
        logs.append("✍️ [HMAC-SHA256] Cryptographic signature generated")
        verdict = AttestationEngine.verify_device(AttestationRequest(
            device_id=dev_id, nonce=nonce, firmware_hash=fw_hash, timestamp=ts, signature=sig
        ))
        logs.append(f"⚖️ [Verdict] {verdict.trust_status}: {verdict.reason}")
        allowed, reason = AttestationEngine.verify_telemetry_access(dev_id, verdict.trust_token)
        logs.append(f"📡 [Gatekeeper Telemetry] Access {'GRANTED (HTTP 200 OK)' if allowed else 'DENIED'}")
        return {"status": "SUCCESS", "verdict": verdict.trust_status, "logs": logs}

    elif scenario_id == 2:
        dev_id = "IOT-DEV-102"
        secret_key = "SECRET_KEY_102_SECURE"
        fw_path = tampered_fw
        logs.append(f"▶️ [Scenario 2] Running Tampered Firmware Attack ({dev_id})")
        nonce, _ = AttestationEngine.issue_challenge(dev_id)
        logs.append(f"🌐 [Challenge] Nonce issued: {nonce}")
        fw_hash = calculate_file_hash(fw_path)
        logs.append(f"⚠️ [Tampered Boot] Altered SHA-256: {fw_hash[:16]}...{fw_hash[-16:]}")
        ts = int(time.time())
        msg = build_canonical_attestation_string(dev_id, nonce, fw_hash, ts)
        sig = generate_hmac_signature(secret_key, msg)
        verdict = AttestationEngine.verify_device(AttestationRequest(
            device_id=dev_id, nonce=nonce, firmware_hash=fw_hash, timestamp=ts, signature=sig
        ))
        logs.append(f"❌ [Verdict] {verdict.trust_status}: {verdict.reason}")
        allowed, reason = AttestationEngine.verify_telemetry_access(dev_id, "NO_TOKEN")
        logs.append(f"⛔ [Gatekeeper Telemetry] BLOCKED (HTTP 403 Forbidden): {reason}")
        return {"status": "BLOCKED", "verdict": verdict.trust_status, "logs": logs}

    elif scenario_id == 3:
        dev_id = "IOT-DEV-103"
        secret_key = "INVALID_ROGUE_KEY"
        fw_path = genuine_fw
        logs.append(f"▶️ [Scenario 3] Running Rogue Key Attack ({dev_id})")
        nonce, _ = AttestationEngine.issue_challenge(dev_id)
        logs.append(f"🌐 [Challenge] Nonce issued: {nonce}")
        fw_hash = calculate_file_hash(fw_path)
        ts = int(time.time())
        msg = build_canonical_attestation_string(dev_id, nonce, fw_hash, ts)
        sig = generate_hmac_signature(secret_key, msg)
        verdict = AttestationEngine.verify_device(AttestationRequest(
            device_id=dev_id, nonce=nonce, firmware_hash=fw_hash, timestamp=ts, signature=sig
        ))
        logs.append(f"❌ [Verdict] {verdict.trust_status}: {verdict.reason}")
        allowed, reason = AttestationEngine.verify_telemetry_access(dev_id, "NO_TOKEN")
        logs.append(f"⛔ [Gatekeeper Telemetry] BLOCKED (HTTP 403 Forbidden): {reason}")
        return {"status": "BLOCKED", "verdict": verdict.trust_status, "logs": logs}

    elif scenario_id == 4:
        dev_id = "IOT-DEV-101"
        secret_key = "SECRET_KEY_101_SECURE"
        fw_path = genuine_fw
        logs.append(f"▶️ [Scenario 4] Running Replay Attack on Nonce ({dev_id})")
        nonce, _ = AttestationEngine.issue_challenge(dev_id)
        fw_hash = calculate_file_hash(fw_path)
        ts = int(time.time())
        msg = build_canonical_attestation_string(dev_id, nonce, fw_hash, ts)
        sig = generate_hmac_signature(secret_key, msg)
        verdict1 = AttestationEngine.verify_device(AttestationRequest(
            device_id=dev_id, nonce=nonce, firmware_hash=fw_hash, timestamp=ts, signature=sig
        ))
        logs.append(f"1️⃣ Legitimate Attestation: Nonce consumed. Verdict: {verdict1.trust_status}")
        logs.append("2️⃣ Attacker replays identical attestation quote using consumed Nonce...")
        verdict2 = AttestationEngine.verify_device(AttestationRequest(
            device_id=dev_id, nonce=nonce, firmware_hash=fw_hash, timestamp=ts, signature=sig
        ))
        logs.append(f"❌ [Verdict] {verdict2.trust_status}: {verdict2.reason}")
        return {"status": "BLOCKED", "verdict": verdict2.trust_status, "logs": logs}

    raise HTTPException(status_code=400, detail="Invalid scenario ID. Choose 1, 2, 3, or 4.")
