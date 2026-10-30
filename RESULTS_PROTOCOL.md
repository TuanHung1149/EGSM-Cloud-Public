# Results Protocol

Paper-version-11 outcomes use one architecture-independent rule for every run:

1. `E`: exact recovery of the run-specific protected flag;
2. `I`: cryptographically valid, run-bound issuance provenance; and
3. `C`: authenticated target-side confirmation of the scenario condition.

A positive outcome is recorded exactly when `E ∧ I ∧ C` holds. The evaluator
applies this rule uniformly across EGSM-Cloud, PentestAgent-style, and
VulnBot-style runs.

The control plane generates a fresh HMAC-derived flag and condition token for
each run. Preserved execution observations supply `E`, archived issuance
records supply `I`, and signed condition events supply `C`.
