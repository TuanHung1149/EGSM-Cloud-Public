import os
from pathlib import Path

from egsm_cloud.verifier import verify_task_execution
from testbed.inject_flags import update_lab_file


def test_verifier_preserves_typed_evidence_and_action_contract():
    task = {
        "id": "task-1",
        "action_id": "action-1",
        "objective_type": "target_reachable",
        "expected_evidence": ["HTTP_STATUS_REACHABLE"],
    }
    verdict = verify_task_execution(
        task,
        [{
            "command": "curl http://target",
            "return_code": 0,
            "http_status": 200,
            "response_headers": {"server": "nginx"},
            "response_snippet": "ok",
            "attributes": {"provenance": "executor"},
        }],
        {},
        {},
    )
    assert verdict["status"] == "verified"
    assert verdict["action_id"] == "action-1"
    assert verdict["missing_evidence"] == []
    assert verdict["evidence_summary"]["artifacts"][0]["http_status"] == 200


def test_exploit_verifier_rejects_internal_parser_delta():
    verdict = verify_task_execution(
        {
            "id": "task-2",
            "action_id": "action-2",
            "objective_type": "exploit_effect_confirmed",
        },
        [{"command": "curl /CVE-2024-0001", "return_code": 1, "stdout": "", "stderr": "failed"}],
        {"vulnerabilities_found": [], "credentials_found": {}},
        {"vulnerabilities_found": [{"id": "command-regex"}], "credentials_found": {}},
    )
    assert verdict["status"] == "unverified"
    assert "EXPLOIT_EFFECT_STATE_CHANGE" not in verdict["matched_rule_ids"]


def test_inject_flags_generates_valid_dynamic_python(tmp_path: Path, monkeypatch):
    cve = "CVE-2024-0001"
    lab = tmp_path / "lab.py"
    lab.write_text(
        '"""Lab module."""\n'
        'def plain():\n'
        f'    return {{"flag": "FLAG{{{cve}_pwned}}"}}\n'
        'def triple():\n'
        f'    return """prefix FLAG{{{cve}_pwned}} suffix"""\n',
        encoding="utf-8",
    )
    ok, message = update_lab_file(lab, cve)
    assert ok, message
    source = lab.read_text(encoding="utf-8")
    assert f"FLAG{{{cve}_pwned}}" not in source
    compile(source, str(lab), "exec")
    monkeypatch.setenv("EGSM_PROTECTED_FLAG", "FLAG{dynamic}")
    namespace = {"os": os}
    exec(source, namespace)
    assert namespace["plain"]()["flag"] == "FLAG{dynamic}"
    assert namespace["triple"]() == "prefix FLAG{dynamic} suffix"
