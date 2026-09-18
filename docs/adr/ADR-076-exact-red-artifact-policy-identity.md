# ADR-076: Exact Red artifacts participate in attack-policy identity

- Status: Accepted
- Date: 2026-09-18

## Context

Role configuration already identifies the Red planner and mutator by provider, model tag,
endpoint and generation settings. Exact local Ollama artifact qualification is stronger:
a mutable tag can resolve to different model bytes over time without changing the role
configuration fingerprint.

For reproducible adversarial measurement this is material. Two campaigns using the same
Red search algorithm and mutable model tags but different exact planner/mutator artifacts
must not share one attack-policy fingerprint.

The HAL offline composition already has exact artifact qualification for all admitted
models. Fresh inventory and saved /api/tags observations are evidence snapshots and should
not themselves become stable attack-policy identity.

## Decision

Derive one `red_measurement_binding_sha256` during HAL offline composition.

The binding contains, separately for planner and mutator:

- logical role model ID;
- role configuration fingerprint;
- exact qualified artifact digest;
- exact artifact identity hash;
- exact artifact-contract hash.

It deliberately excludes:

- fresh OpenWebUI inventory hash;
- fresh /api/tags snapshot hash;
- local admission proof hash;
- per-run runtime observations.

`build_model_backed_red_policy_descriptor()` accepts this binding optionally and includes
it in the immutable Red descriptor. `RedStrategyRuntime` and the standard
`CampaignLifecycleExecutor` propagate the same binding.

Therefore the existing attack-policy fingerprint and measurement snapshot automatically
change when an exact Red artifact changes.

Static Red policies reject a Red measurement binding because no model-backed attacker is
being measured.

The HAL preflight CLI exposes the binding hash so the later live operator path can pass the
exact predeclared Red identity into campaign construction.

## Runtime qualification

This ADR binds the *predeclared exact Red artifact identity*. It does not claim that a
mutable HAL Ollama runtime still serves those bytes at inference time.

The live smoke must still perform the already-declared
`exact_red_runtime_artifact_recheck` before Red inference and bind that runtime evidence
into campaign execution provenance.

## Consequences

Changing a planner or mutator artifact under an unchanged Ollama tag changes the
attack-policy fingerprint.

Refreshing equivalent local inventory evidence does not change the attack-policy
fingerprint.

Blue exact artifact identity remains separate and continues to participate in
`TargetIdentity`; Red exact artifact identity participates in the attack-policy identity.
This preserves the measurement distinction between the system under test and the attacker.
