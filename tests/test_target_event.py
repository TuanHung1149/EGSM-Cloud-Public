import hashlib
import hmac
import json

from testbed.target_event import emit_target_event


def test_emit_target_event_records_eq27_provenance(tmp_path, monkeypatch):
    events_path = tmp_path / "condition_events.jsonl"
    monkeypatch.setenv("EGSM_RUN_ID", "run-123")
    monkeypatch.setenv("EGSM_SCENARIO_ID", "CVE-2026-0001")
    monkeypatch.setenv("EGSM_CONDITION_ID", "condition-1")
    monkeypatch.setenv("EGSM_CONDITION_TOKEN", "ab" * 32)

    event = emit_target_event("FLAG{dynamic}", events_file=str(events_path))

    saved = json.loads(events_path.read_text(encoding="utf-8").strip())
    assert event["run_id"] == "run-123"
    assert saved["scenario_id"] == "CVE-2026-0001"
    assert saved["condition_id"] == "condition-1"
    assert saved["flag_digest"] == hashlib.sha256(b"FLAG{dynamic}").hexdigest()
    signed = {key: value for key, value in saved.items() if key != "condition_mac"}
    expected = hmac.new(
        bytes.fromhex("ab" * 32),
        json.dumps(
            signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(saved["condition_mac"], expected)
