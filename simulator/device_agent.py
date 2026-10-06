import argparse
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
import sys

# Add parent directory to sys.path so we can import crypto utilities
PARENT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PARENT_DIR))

from app.crypto_utils import (
    calculate_file_hash,
    build_canonical_attestation_string,
    generate_hmac_signature,
)

BASE_URL = "http://127.0.0.1:8000"
FIRMWARE_DIR = Path(__file__).resolve().parent / "firmware_samples"
GENUINE_FIRMWARE = FIRMWARE_DIR / "firmware_v1.bin"
TAMPERED_FIRMWARE = FIRMWARE_DIR / "firmware_tampered.bin"


def http_post(endpoint: str, data: dict) -> dict:
    url = f"{BASE_URL}{endpoint}"
    payload_bytes = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload_bytes,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        try:
            return {"_http_status": e.code, "_error": json.loads(error_body)}
        except Exception:
            return {"_http_status": e.code, "_error": error_body}
    except Exception as e:
        return {"_error": str(e)}


class IoTDevice:
    def __init__(self, device_id: str, secret_key: str, firmware_path: Path):
        self.device_id = device_id
        self.secret_key = secret_key
        self.firmware_path = firmware_path
        self.trust_token = None

    def measure_firmware(self) -> str:
        """Simulates TPM Measured Boot: computes cryptographic hash of active binary."""
        print(f"  🔍 [Measured Boot] Hashing firmware binary at: {self.firmware_path.name}")
        firmware_hash = calculate_file_hash(self.firmware_path)
        print(f"  📌 [Measurement Hash]: {firmware_hash[:16]}...{firmware_hash[-16:]}")
        return firmware_hash

    def request_challenge(self) -> str:
        """Step 1: Request fresh challenge nonce from Verifier."""
        print(f"  🌐 [Step 1] Requesting attestation challenge nonce for '{self.device_id}'...")
        res = http_post("/api/challenge", {"device_id": self.device_id})
        if "_error" in res:
            raise RuntimeError(f"Challenge request failed: {res['_error']}")
        nonce = res["nonce"]
        print(f"  🔑 [Challenge Nonce Received]: {nonce}")
        return nonce

    def perform_attestation(self, nonce_override: str = None, tamper_signature: bool = False) -> dict:
        """Step 2: Sign attestation evidence (Quote) and submit to Verifier."""
        nonce = nonce_override or self.request_challenge()
        fw_hash = self.measure_firmware()
        timestamp = int(time.time())

        # Construct canonical string
        canonical = build_canonical_attestation_string(self.device_id, nonce, fw_hash, timestamp)

        # Generate HMAC-SHA256 signature
        if tamper_signature:
            signature = "MALICIOUS_OR_INVALID_SIGNATURE_HEX_CODE"
            print("  ⚠️ [Simulation] Intentionally injecting invalid cryptographic signature!")
        else:
            signature = generate_hmac_signature(self.secret_key, canonical)

        print(f"  📝 [Step 2] Submitting attestation quote to Verifier Engine...")
        payload = {
            "device_id": self.device_id,
            "nonce": nonce,
            "firmware_hash": fw_hash,
            "timestamp": timestamp,
            "signature": signature
        }
        res = http_post("/api/attest", payload)
        
        status = res.get("trust_status", "UNKNOWN")
        allowed = res.get("is_allowed", False)
        reason = res.get("reason", "No reason provided")

        if allowed and res.get("trust_token"):
            self.trust_token = res["trust_token"]
            print(f"  ✅ [Verdict]: \033[92m{status}\033[0m")
            print(f"  🎟️ [Trust Token Granted]: {self.trust_token[:20]}...")
        else:
            self.trust_token = None
            print(f"  ❌ [Verdict]: \033[91m{status}\033[0m")
            print(f"  🛑 [Rejection Reason]: {reason}")

        return res

    def send_telemetry(self, sensor_data: dict) -> dict:
        """Step 3: Attempt to transmit telemetry data through Zero-Trust Gatekeeper."""
        print(f"  📡 [Step 3] Transmitting sensor telemetry to protected service...")
        payload = {
            "device_id": self.device_id,
            "trust_token": self.trust_token or "NO_TOKEN",
            "payload": sensor_data
        }
        res = http_post("/api/telemetry", payload)
        if "_http_status" in res and res["_http_status"] == 403:
            print(f"  ⛔ [Gatekeeper]: \033[91mBLOCKED (HTTP 403 FORBIDDEN)\033[0m")
            print(f"     Details: {res['_error'].get('detail', {}).get('reason')}")
        else:
            print(f"  🚀 [Gatekeeper]: \033[92mACCEPTED (HTTP 200 OK)\033[0m")
            print(f"     Data received: {sensor_data}")
        return res


def run_scenario_1_legitimate():
    print("\n" + "="*70)
    print("▶️ SCENARIO 1: Legitimate Trusted Device (Normal Boot & Authentic Code)")
    print("="*70)
    device = IoTDevice(
        device_id="IOT-DEV-101",
        secret_key="SECRET_KEY_101_SECURE",
        firmware_path=GENUINE_FIRMWARE
    )
    device.perform_attestation()
    device.send_telemetry({"voltage": 220.4, "current_amperes": 4.8, "status": "NOMINAL"})


def run_scenario_2_tampered_firmware():
    print("\n" + "="*70)
    print("▶️ SCENARIO 2: Firmware Tampering Attack (Integrity Violation)")
    print("   [Attacker injected unauthorized code into the device binary]")
    print("="*70)
    device = IoTDevice(
        device_id="IOT-DEV-102",
        secret_key="SECRET_KEY_102_SECURE",
        firmware_path=TAMPERED_FIRMWARE  # Backdoor / Malicious code present!
    )
    device.perform_attestation()
    device.send_telemetry({"temperature": 88.5, "alarm": "CRITICAL"})


def run_scenario_3_rogue_device():
    print("\n" + "="*70)
    print("▶️ SCENARIO 3: Rogue / Imposter Device (Invalid Secret Key)")
    print("   [Attacker attempts to clone device ID with an incorrect key]")
    print("="*70)
    device = IoTDevice(
        device_id="IOT-DEV-103",
        secret_key="HACKER_ATTEMPTED_WRONG_SECRET_KEY",  # Invalid key
        firmware_path=GENUINE_FIRMWARE
    )
    device.perform_attestation()
    device.send_telemetry({"hacked_data": True})


def run_scenario_4_replay_attack():
    print("\n" + "="*70)
    print("▶️ SCENARIO 4: Replay Attack (Attacker replaying old Nonce)")
    print("   [Attacker intercepts an attestation message and tries to replay it]")
    print("="*70)
    device = IoTDevice(
        device_id="IOT-DEV-101",
        secret_key="SECRET_KEY_101_SECURE",
        firmware_path=GENUINE_FIRMWARE
    )
    # Legitimate first run
    print("--- [Pass 1: Legitimate verification consumes Nonce] ---")
    nonce = device.request_challenge()
    device.perform_attestation(nonce_override=nonce)

    # Replay attempt with same nonce
    print("\n--- [Pass 2: Attacker replays identical quote with consumed Nonce] ---")
    device.perform_attestation(nonce_override=nonce)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Trusted Computing Device Simulator")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4, 0], default=0,
                        help="Scenario to run: 1=Legitimate, 2=Tampered, 3=Rogue Key, 4=Replay, 0=Run All")
    args = parser.parse_args()

    print("\n🔐 =================================================================")
    print("    IoT Trusted Computing Simulator - Device Agent Runner")
    print("=================================================================")
    print("Target Verifier Server:", BASE_URL)

    try:
        # Check if server is running
        urllib.request.urlopen(f"{BASE_URL}/", timeout=2)
    except Exception:
        print("\n⚠️ WARNING: Verifier server does not appear to be running at http://127.0.0.1:8000")
        print("Please start the server first using: python run_server.py\n")
        sys.exit(1)

    if args.scenario == 0:
        run_scenario_1_legitimate()
        time.sleep(1)
        run_scenario_2_tampered_firmware()
        time.sleep(1)
        run_scenario_3_rogue_device()
        time.sleep(1)
        run_scenario_4_replay_attack()
    elif args.scenario == 1:
        run_scenario_1_legitimate()
    elif args.scenario == 2:
        run_scenario_2_tampered_firmware()
    elif args.scenario == 3:
        run_scenario_3_rogue_device()
    elif args.scenario == 4:
        run_scenario_4_replay_attack()
