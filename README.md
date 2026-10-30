# EGSM-Cloud

**Evidence-Governed State Management for Autonomous Cloud-Oriented Penetration Testing**

EGSM-Cloud is an autonomous cloud-oriented penetration-testing framework in
which a persistent normalized runner state is the operational authority. A
Typed Agentic Evidence Graph is materialized from committed state to provide
bounded relational context; it is not an independent source of truth. LLM
components propose tasks and commands, while controlled execution,
provider-aware artifact processing, and 17 deterministic objective handlers
decide whether evidence is `verified`, `partial`, or `unverified`.

This repository contains the framework, adapted PentestAgent-style and
VulnBot-style comparison pipelines, the external flag protocol, and evaluation
code accompanying the paper. It is intended only for authorized, isolated
laboratories.

Public data and paper bundle: [EGSM-Cloud Google Drive folder](https://drive.google.com/drive/folders/19v0E8aWT-hqnKJmQ4N7mIlB0aqz0GXfo)

## Architecture

At round `t`, the runner performs the paper's execution-to-state transition:

```text
state -> materialized graph -> bounded summary -> skill routing -> planning
      -> command generation -> controlled execution -> typed evidence
      -> artifact extraction -> objective verification -> committed state
```

The implementation includes:

- 11 graph node types and 13 directed relation types;
- eight deterministic skill families and an 18-example context bank;
- at most two contextual examples per planning round, ranked by
  `10*skill_match + 4*provider_match + 2*stack_match`;
- 17 objective-specific evidence handlers;
- a Planner-facing graph bound of 120 nodes and 220 edges; and
- early stopping after three completed rounds with an unchanged canonical
  committed-progress signature.

Only verified findings are confirmed planning preconditions. Partial and
unverified observations may remain in the trace with provenance, but do not
establish objective completion.

## Repository Layout

```text
egsm_cloud/
  schema.py                typed action, evidence, graph, and verifier records
  graph.py                 state-derived graph and canonical progress signature
  skill_router.py          eight-family router and contextual-example retrieval
  verifier.py              17 deterministic objective handlers
  scope_guard.py           target, command, and budget checks
  orchestrator.py          Planner-to-commit execution loop
  rag/                     optional CVE-context retrieval
  fewshot/                 18 contextual Planner examples
baselines/
  pentestagent.py          adapted PentestAgent-style pipeline
  vulnbot.py               adapted VulnBot-style pipeline
testbed/
  flag_issuer.py           run-specific HMAC flag issuance (paper Eq. 26)
  provision.py             control-plane manifest and target environment setup
  target_event.py          target-side Eq. 27 provenance event writer
  flag_oracle.py           common external outcome evaluator (paper Eq. 27)
evaluation/
  compute_metrics.py       FRR, consistency, telemetry, and efficiency metrics
```

## Installation

```bash
git clone https://github.com/TuanHung1149/EGSM-Cloud-Public.git
cd EGSM-Cloud-Public
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Planner and Generator calls use an OpenAI-compatible chat-completions endpoint.
API keys are supplied at runtime and must not be committed.

```bash
export API_URL="http://localhost:8000/v1"
export API_KEY="..."

python -m egsm_cloud.orchestrator \
  --api-url "$API_URL" \
  --api-key "$API_KEY" \
  --target-url "http://localhost:8080" \
  --target "authorized cloud security laboratory" \
  --max-rounds 15
```

## External Outcome Protocol

Each architecture-backbone-scenario run receives a fresh protected flag:

```text
phi(i,r) = FLAG{ Hex[ HMAC(k_i, run_id || nonce) ] }
```

`k_i`, the expected flag, and validation metadata remain in the evaluation
control plane. The assessed pipeline receives none of them. Issuance provenance
is archived separately, and the target writes an authenticated
`condition_events.jsonl` event when the protected condition releases the flag.

The oracle reports a positive outcome only when all conditions in paper Eq. 27
hold:

1. `E`: the exact run-specific flag occurs in retained execution observations;
2. `I`: its run-bound issuance provenance is cryptographically valid; and
3. `C`: an authenticated target-side event confirms the scenario condition.

```bash
python -m testbed.provision \
  --cve-list cves.txt \
  --results-dir results/egsm-qwen-base \
  --architecture EGSM-Cloud \
  --backbone Qwen2.5-32B-base

python -m testbed.flag_oracle results/egsm-qwen-base
python evaluation/compute_metrics.py results/egsm-qwen-base
```

The manifest, issuance provenance, and condition events are evaluation-control
artifacts and are ignored by Git.

## Metrics

The primary outcome is **Flag Recovery Rate (FRR)**. ECAR and VIDR are
operational telemetry, not exploitation-success measures. `Tok@T` is reported
as median `[Q1, Q3]`; `Tok@Req`, `Req@F`, `Tok@F`, FPMT, and FPkR are pooled
ratios.

The paper evaluates 86 validated Docker scenarios under three architectures and
six LLM configurations, for 1,548 runs. EGSM-Cloud recovers 53 flags in its 516
runs (FRR 10.3%; CVE-cluster bootstrap 95% interval 4.7-16.9%). The adapted
PentestAgent-style and VulnBot-style pipelines each recover 0/516 flags. These
figures report outcomes under the paper's controlled protocol.

## Release Contents

This repository provides the framework, comparison implementations, evaluation
code, and protocol tests. The companion public Drive release provides the
Planner-specialisation corpus, scenario archive, paper source, and benchmark
tables while control-plane secrets remain isolated from assessed pipelines.

## Responsible Use

Use EGSM-Cloud only against systems for which you have explicit authorization.
The paper's experiments use freshly provisioned, researcher-controlled Docker
laboratories, scenario-scoped credentials, timeouts, bounded output capture, and
non-destructive policies. The controls reduce risk but are not a formally
verified sandbox for arbitrary untrusted code.

## Citation

```bibtex
@article{nguyen2026egsmcloud,
  title  = {EGSM-Cloud: Evidence-Governed State Management for Autonomous
            Cloud-Oriented Penetration Testing},
  author = {Nguyen Tuan, Hung and Phan Thi Nhu, Huynh and
            Le Pham Khanh, Linh and Nguyen Thi My, Duyen and
            Nguyen Huu, Quyen and Pham, Van-Hau},
  year   = {2026}
}
```

## License

Released under the [Apache License 2.0](LICENSE).
