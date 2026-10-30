#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

CONTROL_PLANE = Path(
    os.environ.get("EGSM_CONTROL_PLANE", Path(__file__).with_name("control_plane"))
)
SECRETS_FILE = CONTROL_PLANE / "scenario_secrets.json"
PROVENANCE_FILE = CONTROL_PLANE / "provenance.jsonl"

_SECRET_BYTES = 32
_NONCE_BYTES = 16
_CONDITION_TOKEN_BYTES = 32


def _canonical_json(value: Dict[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _load_secrets() -> Dict[str, str]:
    if SECRETS_FILE.exists():
        return json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
    return {}


def _scenario_secret(scenario_id: str, store: Dict[str, str]) -> bytes:
    if scenario_id not in store:
        store[scenario_id] = secrets.token_hex(_SECRET_BYTES)
        CONTROL_PLANE.mkdir(parents=True, exist_ok=True)
        SECRETS_FILE.write_text(
            json.dumps(store, indent=2, sort_keys=True), encoding="utf-8"
        )
    return bytes.fromhex(store[scenario_id])


def derive_flag(secret_k: bytes, run_id: str, nonce: str) -> str:
    mac = hmac.new(secret_k, f"{run_id}||{nonce}".encode("utf-8"), hashlib.sha256)
    return f"FLAG{{{mac.hexdigest()}}}"


def _provenance_fields(record: Dict[str, object]) -> Dict[str, object]:
    return {
        "run_id": record["run_id"],
        "scenario_id": record["scenario_id"],
        "nonce": record["nonce"],
        "flag_digest": record["flag_digest"],
        "condition_token_digest": record["condition_token_digest"],
        "condition_id": record["condition_id"],
        "issued_at": record["issued_at"],
    }


def verify_issuance_record(record: Dict[str, object]) -> bool:
    try:
        store = _load_secrets()
        scenario_id = str(record["scenario_id"])
        secret_k = bytes.fromhex(store[scenario_id])
        expected_flag = derive_flag(
            secret_k, str(record["run_id"]), str(record["nonce"])
        )
        if not hmac.compare_digest(expected_flag, str(record["flag"])):
            return False
        expected_digest = hashlib.sha256(expected_flag.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected_digest, str(record["flag_digest"])):
            return False
        expected_mac = hmac.new(
            secret_k,
            _canonical_json(_provenance_fields(record)),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected_mac, str(record["provenance_mac"]))
    except (KeyError, TypeError, ValueError):
        return False


def issue_flag(scenario_id: str, run_id: Optional[str] = None) -> Dict[str, object]:
    store = _load_secrets()
    secret_k = _scenario_secret(scenario_id, store)
    run_id = run_id or f"{scenario_id}-{secrets.token_hex(8)}"
    nonce = secrets.token_hex(_NONCE_BYTES)
    flag = derive_flag(secret_k, run_id, nonce)
    condition_token = secrets.token_hex(_CONDITION_TOKEN_BYTES)
    condition_id = f"{scenario_id}:protected_flag_released"

    record = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "nonce": nonce,
        "flag": flag,
        "flag_digest": hashlib.sha256(flag.encode("utf-8")).hexdigest(),
        "condition_token": condition_token,
        "condition_token_digest": hashlib.sha256(
            condition_token.encode("utf-8")
        ).hexdigest(),
        "condition_id": condition_id,
        "issued_at": time.time(),
    }
    record["provenance_mac"] = hmac.new(
        secret_k,
        _canonical_json(_provenance_fields(record)),
        hashlib.sha256,
    ).hexdigest()

    CONTROL_PLANE.mkdir(parents=True, exist_ok=True)
    (CONTROL_PLANE / f"{run_id}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    with open(PROVENANCE_FILE, "a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "nonce": record["nonce"],
                    "issued_at": record["issued_at"],
                    "flag_digest": record["flag_digest"],
                    "condition_token_digest": record["condition_token_digest"],
                    "condition_id": record["condition_id"],
                    "provenance_mac": record["provenance_mac"],
                }
            )
            + "\n"
        )
    return record


def expected_flag(run_id: str) -> str:
    rec = json.loads((CONTROL_PLANE / f"{run_id}.json").read_text(encoding="utf-8"))
    return rec["flag"]


def load_issuance_record(run_id: str) -> Dict[str, object]:
    path = CONTROL_PLANE / f"{run_id}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid issuance record: {path}")
    return value


def _demo() -> int:
    a = issue_flag("CVE-0000-0000", run_id="demo-a")
    b = issue_flag("CVE-0000-0000", run_id="demo-b")
    assert a["flag"] != b["flag"], "run-specific flags must differ"
    assert a["flag"].startswith("FLAG{") and a["flag"].endswith("}")
    assert verify_issuance_record(a)
    assert verify_issuance_record(b)
    print("issue_flag OK — two runs, two distinct flags:")
    print("  run demo-a:", a["flag"])
    print("  run demo-b:", b["flag"])
    return 0


if __name__ == "__main__":
    raise SystemExit(_demo())
