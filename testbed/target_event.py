#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict


DEFAULT_EVENTS_FILE = "condition_events.jsonl"


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def build_target_event(
    issued_flag: str | None = None,
    *,
    condition_satisfied: bool = True,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    run_id = os.environ.get("EGSM_RUN_ID", "").strip()
    scenario_id = os.environ.get("EGSM_SCENARIO_ID", "").strip()
    condition_id = (
        os.environ.get("EGSM_CONDITION_ID", "").strip()
        or os.environ.get("EGSM_SECURITY_CONDITION_ID", "").strip()
    )
    token = os.environ.get("EGSM_CONDITION_TOKEN", "").strip()
    flag = issued_flag or os.environ.get("EGSM_PROTECTED_FLAG", "").strip()
    if not all((run_id, scenario_id, condition_id, token, flag)):
        raise ValueError("missing run, scenario, condition, token, or flag")
    if not condition_satisfied:
        raise ValueError("condition_satisfied must be true")

    event: Dict[str, Any] = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "condition_id": condition_id,
        "flag_digest": hashlib.sha256(flag.encode("utf-8")).hexdigest(),
        "confirmed_at": time.time(),
    }
    if extra:
        event.update(extra)
    event["condition_mac"] = hmac.new(
        bytes.fromhex(token), _canonical_json(event), hashlib.sha256
    ).hexdigest()
    return event


def emit_target_event(
    issued_flag: str | None = None,
    *,
    condition_satisfied: bool = True,
    events_file: str | None = None,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    path = Path(
        events_file
        or os.environ.get("EGSM_CONDITION_EVENT_FILE", "")
        or DEFAULT_EVENTS_FILE
    )
    event = build_target_event(
        issued_flag,
        condition_satisfied=condition_satisfied,
        extra=extra,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, _canonical_json(event) + b"\n")
    finally:
        os.close(fd)
    return event
