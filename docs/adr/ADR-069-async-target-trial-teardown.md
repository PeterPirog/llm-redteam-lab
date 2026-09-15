# ADR-069: Target-trial teardown is awaitable when the provider requires it

Status: Proposed

Date: 2026-09-15

## Context

The final disposable OpenCode target will own asynchronous client/transport state. In
particular, `DockerExecOpenCodeTarget.aclose()` must complete before the AGENT container,
model peer, network and disposable workspace can be reported as fully cleaned up.

The established `TargetTrialLeaseProvider` contract predates that runtime and exposes a
synchronous `release()` method. Existing in-memory providers are correctly synchronous and
must remain source- and behavior-compatible. Starting a nested event loop from a
synchronous Docker provider would be invalid because attacker-pool execution already runs
inside an async event loop.

## Decision

Introduce `release_target_trial_lease()` as the single async campaign teardown boundary.

- If a provider exposes callable `release_async(lease)`, the helper requires an awaitable
  result and awaits it to completion.
- Otherwise the helper calls the existing synchronous `release(lease)` method unchanged.
- The returned object must be `TargetTrialIsolationRelease` and must bind the exact acquired
  `lease_id_hash`.
- No `asyncio.run()` or nested event loop is used by production lifecycle code.

`PersistedAttackerPoolRunner` now awaits this boundary both after a normal trial and while
cleaning up an acquisition that fails lease validation. Existing synchronous providers
therefore preserve their behavior while future disposable providers can close async target
resources before reporting infrastructure cleanup.

## Consequences

A future Docker provider can implement the required teardown ordering:

1. await target transport/client close;
2. remove and verify the OpenCode AGENT container;
3. remove and verify the staged Ollama model peer;
4. remove and verify the isolated Docker network;
5. remove/verify disposable workspace state;
6. only then return `cleanup_complete=true`.

Campaign persistence continues to record release evidence only after the provider release
has completed.

## Follow-up

Build the concrete `DISPOSABLE_SANDBOX` OpenCode lease provider using this awaitable
teardown boundary and the already merged model-peer, OpenCode environment, health and
Docker-exec transport proofs.
