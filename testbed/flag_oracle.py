#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping

try:
    from testbed.flag_issuer import load_issuance_record, verify_issuance_record
except ModuleNotFoundError:
    from flag_issuer import load_issuance_record, verify_issuance_record

MANIFEST_NAME = "flags_expected.json"
PROVENANCE_NAME = "issuance_provenance.jsonl"
CONDITION_EVENTS_NAME = "condition_events.jsonl"
FLAG_RE = re.compile(r"^FLAG\{[0-9a-f]{64}\}$")


@dataclass(frozen=True)
class Outcome:
    scenario_id: str
    run_id: str
    exact_recovery: bool
    issuance_provenance: bool
    condition_confirmation: bool
    success: bool
    reason: str = ""


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _read_jsonl(path: Path) -> List[dict]:
    if not path.is_file():
        return []
    rows: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def load_manifest(results_dir: str) -> Dict[str, dict]:
    path = Path(results_dir) / MANIFEST_NAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 2:
        raise ValueError(f"{path}: schema_version=2 is required")
    if payload.get("success_criterion") != "E_and_I_and_C":
        raise ValueError(f"{path}: success_criterion must be E_and_I_and_C")
    runs = payload.get("runs")
    if not isinstance(runs, dict):
        raise ValueError(f"{path}: runs must be an object")
    return runs


def _raw_artifacts(results_dir: Path, scenario_id: str) -> Iterable[Path]:
    for suffix in ("_exec.json", "_output.txt"):
        path = results_dir / f"{scenario_id}{suffix}"
        if path.is_file():
            yield path


def _check_exact_recovery(results_dir: Path, scenario_id: str, flag: str) -> bool:
    if not FLAG_RE.fullmatch(flag):
        return False
    return any(
        flag in path.read_text(encoding="utf-8", errors="ignore")
        for path in _raw_artifacts(results_dir, scenario_id)
    )


def _check_provenance(record: dict, provenance_rows: List[dict]) -> bool:
    if not verify_issuance_record(record):
        return False
    public_fields = {
        key: record.get(key)
        for key in (
            "run_id",
            "scenario_id",
            "nonce",
            "flag_digest",
            "condition_token_digest",
            "condition_id",
            "issued_at",
            "provenance_mac",
        )
    }
    return any(
        all(row.get(key) == value for key, value in public_fields.items())
        for row in provenance_rows
    )


def _check_condition(record: dict, condition_rows: List[dict]) -> bool:
    try:
        secure_record = load_issuance_record(str(record["run_id"]))
        if any(
            secure_record.get(key) != record.get(key)
            for key in (
                "run_id",
                "scenario_id",
                "nonce",
                "flag",
                "flag_digest",
                "condition_token_digest",
                "condition_id",
                "issued_at",
                "provenance_mac",
            )
        ):
            return False
        token = str(secure_record["condition_token"])
        expected_token_digest = str(record["condition_token_digest"])
        if not hmac.compare_digest(
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expected_token_digest,
        ):
            return False
        for row in condition_rows:
            if not all(
                (
                    row.get("run_id") == record.get("run_id"),
                    row.get("scenario_id") == record.get("scenario_id"),
                    row.get("condition_id") == record.get("condition_id"),
                    row.get("flag_digest") == record.get("flag_digest"),
                )
            ):
                continue
            confirmed_at = float(row.get("confirmed_at", 0))
            if confirmed_at < float(record["issued_at"]):
                continue
            signed = {key: value for key, value in row.items() if key != "condition_mac"}
            expected_mac = hmac.new(
                bytes.fromhex(token), _canonical_json(signed), hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(expected_mac, str(row.get("condition_mac", ""))):
                return True
    except (KeyError, OSError, TypeError, ValueError):
        return False
    return False


def evaluate_results(results_dir: str) -> List[Outcome]:
    base = Path(results_dir)
    runs = load_manifest(results_dir)
    provenance_rows = _read_jsonl(base / PROVENANCE_NAME)
    condition_rows = _read_jsonl(base / CONDITION_EVENTS_NAME)
    outcomes: List[Outcome] = []

    for scenario_id, record in sorted(runs.items()):
        if not isinstance(record, dict) or record.get("scenario_id") != scenario_id:
            outcomes.append(
                Outcome(
                    scenario_id, "", False, False, False, False,
                    "invalid manifest binding",
                )
            )
            continue
        run_id = str(record.get("run_id", ""))
        exact = _check_exact_recovery(base, scenario_id, str(record.get("flag", "")))
        issued = _check_provenance(record, provenance_rows)
        condition = _check_condition(record, condition_rows)
        missing = [
            name
            for name, ok in (("E", exact), ("I", issued), ("C", condition))
            if not ok
        ]
        outcomes.append(
            Outcome(
                scenario_id,
                run_id,
                exact,
                issued,
                condition,
                exact and issued and condition,
                "" if not missing else "missing/invalid " + ",".join(missing),
            )
        )
    return outcomes


def recovered_flags(
    results_dir: str, expected: Dict[str, dict] | None = None
) -> List[str]:
    del expected
    return [row.scenario_id for row in evaluate_results(results_dir) if row.success]


def main(argv: List[str]) -> int:
    if not argv:
        print("usage: python -m testbed.flag_oracle RESULTS_DIR [RESULTS_DIR ...]")
        return 1
    exit_code = 0
    for results_dir in argv:
        try:
            outcomes = evaluate_results(results_dir)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            print(f"{results_dir}: invalid control-plane evidence: {exc}", file=sys.stderr)
            exit_code = 2
            continue
        hits = [row for row in outcomes if row.success]
        total = len(outcomes)
        frr = 100.0 * len(hits) / total if total else 0.0
        print(f"{results_dir}: EIC-FRR = {len(hits)}/{total} = {frr:.1f}%")
        for row in outcomes:
            mark = "+" if row.success else "-"
            suffix = f" ({row.reason})" if row.reason else ""
            print(
                f"    {mark} {row.scenario_id}: E={int(row.exact_recovery)} "
                f"I={int(row.issuance_provenance)} "
                f"C={int(row.condition_confirmation)}{suffix}"
            )
        (Path(results_dir) / "eic_outcomes.json").write_text(
            json.dumps(
                [asdict(row) for row in outcomes], indent=2, sort_keys=True
            ),
            encoding="utf-8",
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
