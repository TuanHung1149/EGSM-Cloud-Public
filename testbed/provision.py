#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Mapping

from testbed.flag_issuer import issue_flag

ENV_VAR = "EGSM_PROTECTED_FLAG"
MANIFEST_NAME = "flags_expected.json"
PROVENANCE_NAME = "issuance_provenance.jsonl"
MANIFEST_SCHEMA_VERSION = 2


def _public_provenance(record: Mapping[str, object]) -> Dict[str, object]:
    keys = (
        "run_id",
        "scenario_id",
        "nonce",
        "flag_digest",
        "condition_token_digest",
        "condition_id",
        "issued_at",
        "provenance_mac",
    )
    return {key: record[key] for key in keys}


def _manifest_record(record: Mapping[str, object]) -> Dict[str, object]:
    return {
        key: value
        for key, value in record.items()
        if key != "condition_token"
    }


def _target_environment(record: Mapping[str, object]) -> Dict[str, str]:
    return {
        ENV_VAR: str(record["flag"]),
        "EGSM_RUN_ID": str(record["run_id"]),
        "EGSM_SCENARIO_ID": str(record["scenario_id"]),
        "EGSM_CONDITION_ID": str(record["condition_id"]),
        "EGSM_CONDITION_TOKEN": str(record["condition_token"]),
        "EGSM_CONDITION_EVENT_FILE": "/egsm-control/condition_events.jsonl",
    }


def _write_control_artifacts(
    out_dir: Path, records: Mapping[str, Mapping[str, object]]
) -> None:
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "success_criterion": "E_and_I_and_C",
        "runs": records,
    }
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    (out_dir / PROVENANCE_NAME).write_text(
        "".join(
            json.dumps(_public_provenance(row), sort_keys=True) + "\n"
            for row in records.values()
        ),
        encoding="utf-8",
    )


def provision_scenario(scenario_id: str, results_dir: str) -> Dict[str, str]:
    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records: Dict[str, Dict[str, object]] = {}
    manifest_path = out_dir / MANIFEST_NAME
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            existing.get("schema_version") != MANIFEST_SCHEMA_VERSION
            or existing.get("success_criterion") != "E_and_I_and_C"
            or not isinstance(existing.get("runs"), dict)
        ):
            raise ValueError(f"refusing to append to incompatible {manifest_path}")
        records.update(existing["runs"])

    record = issue_flag(scenario_id)
    records[scenario_id] = _manifest_record(record)
    _write_control_artifacts(out_dir, records)
    return _target_environment(record)


def provision_run(
    scenario_ids: List[str],
    results_dir: str,
    architecture: str = "",
    backbone: str = "",
) -> Dict[str, Dict[str, str]]:
    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    env_by_scenario: Dict[str, Dict[str, str]] = {}
    expected: Dict[str, Dict[str, object]] = {}
    for cve in scenario_ids:
        rec = issue_flag(cve)
        env_by_scenario[cve] = _target_environment(rec)
        manifest_record = _manifest_record(rec)
        if architecture:
            manifest_record["architecture"] = architecture
        if backbone:
            manifest_record["backbone"] = backbone
        expected[cve] = manifest_record
    _write_control_artifacts(out_dir, expected)
    return env_by_scenario


def _write_env_file(path: str, env: Mapping[str, str], results_dir: str) -> None:
    values = dict(env)
    values["EGSM_CONDITION_EVENTS_DIR"] = str(Path(results_dir).resolve())
    for key, value in values.items():
        if "\n" in value or "\r" in value:
            raise ValueError(f"invalid newline in environment value {key}")
    env_path = Path(path)
    env_path.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    os.chmod(env_path, 0o600)


def _read_scenarios(cve_list_path: str) -> List[str]:
    text = Path(cve_list_path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip().startswith("CVE-")]


def main() -> int:
    ap = argparse.ArgumentParser(description="Provision run-specific protected flags.")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--cve-list", help="file with one CVE id per line")
    source.add_argument("--scenario", help="provision one CVE id incrementally")
    ap.add_argument("--results-dir", required=True, help="run output directory")
    ap.add_argument("--architecture", default="", help="architecture label")
    ap.add_argument("--backbone", default="", help="backbone label")
    ap.add_argument(
        "--env-file",
        help="write a mode-0600 Docker Compose env file (requires --scenario)",
    )
    args = ap.parse_args()

    if args.scenario:
        env = provision_scenario(args.scenario, args.results_dir)
        if args.env_file:
            _write_env_file(args.env_file, env, args.results_dir)
        print(f"Provisioned {args.scenario}; manifest -> {args.results_dir}/{MANIFEST_NAME}")
        return 0
    if args.env_file:
        ap.error("--env-file requires --scenario")

    scenarios = _read_scenarios(args.cve_list)
    env_map = provision_run(
        scenarios,
        args.results_dir,
        architecture=args.architecture,
        backbone=args.backbone,
    )
    print(f"Provisioned {len(env_map)} scenarios; manifest -> {args.results_dir}/flags_expected.json")
    print("Pass each scenario's EGSM_PROTECTED_FLAG to its container, e.g.:")
    sample = next(iter(env_map.items()), None)
    if sample:
        cve, env = sample
        print(f"  docker run -e {ENV_VAR}={env[ENV_VAR]} ...   # {cve}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
