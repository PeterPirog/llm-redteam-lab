# ADR-066: Carry inference scope at the reference reporting boundary

- Status: Proposed
- Date: 2026-09-13

## Context

The laboratory already distinguishes `FIXED_CORPUS` from `GENERALIZED_POPULATION` inference and fails closed when the standard evaluation summarizer is asked to make a generalized-population claim. Reference Evaluation v1 likewise accepts only `FIXED_CORPUS`.

The operator-facing `reference-run` result previously emitted ASR, model-compromise rate, system-compromise rate and paired-effect statistics without carrying that inference scope in the result itself. A numerically correct result could therefore be copied or consumed downstream without its intended interpretation.

NIST AI 800-3 distinguishes performance on a fixed benchmark from generalized performance over a broader population and requires the evaluation target and uncertainty semantics to be explicit. The laboratory should therefore preserve inference scope through the reporting boundary, not only inside statistical helper code.

## Decision

Reference Evaluation v1 result payloads MUST carry a `measurement_claim` object containing:

- `inference_scope=FIXED_CORPUS`;
- `generalized_claim_supported=false`;
- the metric-definition version used by the campaign;
- the paired statistical unit;
- an explicit interpretation that the estimates describe the exact held-out manifest under the recorded target, Red policy, Judge and budget conditions.

The human-readable CLI MUST also surface the inference scope and whether a generalized claim is supported.

This metadata does not alter ASR/MCR/SCR, paired deltas, confidence calculations or policy qualification. It describes the admissible interpretation of those values.

## Consequences

- Fixed-corpus results are harder to misrepresent when exported or copied out of the CLI.
- Downstream reporting can reject unsupported generalized claims without reconstructing experiment semantics from configuration files.
- A future generalized-population backend must explicitly replace this claim contract with a predeclared sampling/modeling design; it cannot silently reinterpret existing fixed-corpus rates.
- The project does not add a GLMM backend merely because GLMMs are useful. Generalized inference remains blocked until its population, sampling assumptions, estimand and statistical model are deliberately specified and tested.
