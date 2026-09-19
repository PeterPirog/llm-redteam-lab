# ADR-079: First HAL smoke is one fail-closed campaign orchestration boundary

- Status: Accepted
- Date: 2026-09-19

## Context

The repository now has independently tested primitives for:

- offline HAL smoke composition;
- exact local model admission and artifact qualification;
- stable Red artifact attack-policy identity;
- live non-inference Red artifact recheck;
- campaign-scoped isolated Blue model infrastructure;
- exact Blue runtime artifact proof;
- disposable per-trial OpenCode AGENT isolation;
- immutable standard-campaign execution provenance;
- standard model-backed Red/Judge campaign lifecycle.

Leaving the operator to manually connect those primitives would create ordering and evidence
binding risks even if every individual component is correct.

The first live smoke intentionally has a narrow scope: CODING/AGENT, model-backed Red,
OpenCode target-managed session history, no agent network, no git publication, no cloud
fallback and exact local artifacts.

## Decision

Add `HalSmokeCampaignRunner` as the orchestration boundary for the first live smoke.

### Static validation

At runner construction, fail before runtime activity unless:

- the current model configuration recreates the exact offline static plan;
- local admission proof equals the offline composition;
- exact artifact qualification equals the offline composition and binds the admission;
- staged Blue store equals the composition;
- Blue artifact contract names the exact model and manifest digest.

At campaign start, require:

- `TargetClass.CODING`;
- `TargetMode.AGENT`;
- model-backed Red;
- `SessionMode.TARGET_MANAGED`, as required by OpenCode durable sessions;
- agent network disabled;
- git publication disabled.

### Runtime order

For one campaign:

1. launch and attest the campaign-scoped isolated Blue model network and staged Ollama peer;
2. construct the per-trial disposable OpenCode lease provider;
3. immediately before Red inference, recheck Red planner/mutator via non-inference
   `GET /api/tags`;
4. compose immutable pre-inference execution provenance;
5. run `CampaignLifecycleExecutor` with the stable Red measurement binding and the
   disposable target provider;
6. require all per-trial leases to be released by the lifecycle;
7. release the campaign-scoped Blue peer and network;
8. return only after campaign-scoped cleanup is complete.

If Red recheck or campaign execution fails after Blue infrastructure exists, campaign-scoped
cleanup is still attempted.

### Provenance layers

The campaign persists exactly four campaign-scoped pre-inference descriptors:

- `local_model_admission_v1`;
- `model_artifact_qualification_v1`;
- `red_runtime_artifact_recheck_v1`;
- `hal_blue_infrastructure_v1`.

The Blue infrastructure descriptor contains only hash-safe identities and proofs: composition,
network profile/ID hashes, peer profile/container hashes, staged-store identity and exact Blue
artifact proof.

Per-trial OpenCode container environment, health, network membership, disposable workspace and
teardown evidence remain in target-isolation attestations. They are intentionally not promoted
to campaign-scoped provenance.

### Failure and cleanup semantics

A successful orchestration result is returned only if:

- the campaign lifecycle completed according to its own terminal-status rules; and
- campaign-scoped Blue teardown reports `cleanup_complete=true`.

If campaign execution and infrastructure cleanup both fail, the runner raises one explicit
orchestration error retaining the campaign failure as its cause and naming the cleanup failure.

## Consequences

The first HAL smoke no longer depends on an operator manually transferring hashes or choosing
runtime order.

The entire orchestration can be tested in CI with fake infrastructure, fake `/api/tags`,
scripted Red models and synthetic disposable AGENT targets. No Docker daemon, GPU or model
inference is required for CI.

The next step after this runner is operator wiring to real HAL evidence and the first bounded
instrumentation execution; that is the point where local HAL access becomes materially
necessary.
