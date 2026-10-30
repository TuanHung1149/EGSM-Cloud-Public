import hashlib
import hmac
import json

from testbed import flag_issuer
from testbed.flag_oracle import evaluate_results
from testbed.provision import provision_scenario


def _bind_control_plane(monkeypatch, path):
    monkeypatch.setattr(flag_issuer, "CONTROL_PLANE", path)
    monkeypatch.setattr(flag_issuer, "SECRETS_FILE", path / "scenario_secrets.json")
    monkeypatch.setattr(flag_issuer, "PROVENANCE_FILE", path / "provenance.jsonl")


def _condition_event(record):
    event = {
        "run_id": record["run_id"],
        "scenario_id": record["scenario_id"],
        "condition_id": record["condition_id"],
        "flag_digest": record["flag_digest"],
        "confirmed_at": float(record["issued_at"]) + 1.0,
    }
    payload = json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    event["condition_mac"] = hmac.new(
        bytes.fromhex(record["condition_token"]), payload, hashlib.sha256
    ).hexdigest()
    return event


def test_success_requires_e_and_i_and_c(tmp_path, monkeypatch):
    control = tmp_path / "control"
    results = tmp_path / "results"
    _bind_control_plane(monkeypatch, control)
    env = provision_scenario("CVE-2025-0001", str(results))
    record = flag_issuer.load_issuance_record(env["EGSM_RUN_ID"])
    manifest = json.loads((results / "flags_expected.json").read_text())

    assert manifest["success_criterion"] == "E_and_I_and_C"
    assert "condition_token" not in manifest["runs"]["CVE-2025-0001"]

    (results / "CVE-2025-0001_exec.json").write_text(
        json.dumps({"stdout": record["flag"]}), encoding="utf-8"
    )
    outcome = evaluate_results(str(results))[0]
    assert outcome.exact_recovery
    assert outcome.issuance_provenance
    assert not outcome.condition_confirmation
    assert not outcome.success

    event = _condition_event(record)
    (results / "condition_events.jsonl").write_text(
        json.dumps(event) + "\n", encoding="utf-8"
    )
    outcome = evaluate_results(str(results))[0]
    assert outcome.exact_recovery
    assert outcome.issuance_provenance
    assert outcome.condition_confirmation
    assert outcome.success


def test_tampered_condition_event_fails_closed(tmp_path, monkeypatch):
    control = tmp_path / "control"
    results = tmp_path / "results"
    _bind_control_plane(monkeypatch, control)
    env = provision_scenario("CVE-2025-0002", str(results))
    record = flag_issuer.load_issuance_record(env["EGSM_RUN_ID"])
    (results / "CVE-2025-0002_output.txt").write_text(
        str(record["flag"]), encoding="utf-8"
    )
    event = _condition_event(record)
    event["condition_id"] = "CVE-2025-0002:forged"
    (results / "condition_events.jsonl").write_text(
        json.dumps(event) + "\n", encoding="utf-8"
    )

    outcome = evaluate_results(str(results))[0]
    assert outcome.exact_recovery
    assert outcome.issuance_provenance
    assert not outcome.condition_confirmation
    assert not outcome.success


def test_missing_exact_flag_fails_closed(tmp_path, monkeypatch):
    control = tmp_path / "control"
    results = tmp_path / "results"
    _bind_control_plane(monkeypatch, control)
    env = provision_scenario("CVE-2025-0003", str(results))
    record = flag_issuer.load_issuance_record(env["EGSM_RUN_ID"])
    event = _condition_event(record)
    (results / "condition_events.jsonl").write_text(
        json.dumps(event) + "\n", encoding="utf-8"
    )
    (results / "CVE-2025-0003_exec.json").write_text(
        json.dumps({"stdout": "FLAG{CVE-2025-0003_pwned}"}), encoding="utf-8"
    )

    outcome = evaluate_results(str(results))[0]
    assert not outcome.exact_recovery
    assert outcome.issuance_provenance
    assert outcome.condition_confirmation
    assert not outcome.success


def test_missing_issuance_provenance_fails_closed(tmp_path, monkeypatch):
    control = tmp_path / "control"
    results = tmp_path / "results"
    _bind_control_plane(monkeypatch, control)
    env = provision_scenario("CVE-2025-0005", str(results))
    record = flag_issuer.load_issuance_record(env["EGSM_RUN_ID"])
    (results / "CVE-2025-0005_exec.json").write_text(
        json.dumps({"stdout": record["flag"]}), encoding="utf-8"
    )
    (results / "condition_events.jsonl").write_text(
        json.dumps(_condition_event(record)) + "\n", encoding="utf-8"
    )
    (results / "issuance_provenance.jsonl").write_text("", encoding="utf-8")

    outcome = evaluate_results(str(results))[0]
    assert outcome.exact_recovery
    assert not outcome.issuance_provenance
    assert outcome.condition_confirmation
    assert not outcome.success


def test_target_hook_emits_authenticated_condition_event(tmp_path, monkeypatch):
    from testbed.target_event import emit_target_event

    flag = "FLAG{" + "a" * 64 + "}"
    token = "b" * 64
    event_file = tmp_path / "condition_events.jsonl"
    values = {
        "EGSM_PROTECTED_FLAG": flag,
        "EGSM_RUN_ID": "run-1",
        "EGSM_SCENARIO_ID": "CVE-2025-0004",
        "EGSM_CONDITION_ID": "CVE-2025-0004:protected_flag_released",
        "EGSM_CONDITION_TOKEN": token,
        "EGSM_CONDITION_EVENT_FILE": str(event_file),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)

    emit_target_event(flag, events_file=str(event_file))
    event = json.loads(event_file.read_text())
    signed = {key: value for key, value in event.items() if key != "condition_mac"}
    payload = json.dumps(
        signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    expected = hmac.new(bytes.fromhex(token), payload, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(event["condition_mac"], expected)
