# ADR-081: Live HAL smoke has an explicit prepare/execute operator boundary

- Status: Accepted
- Date: 2026-09-19

## Context

The first HAL smoke now has a complete measured campaign lifecycle, exact Red/Blue artifact
identity, campaign-scoped infrastructure, disposable per-trial OpenCode isolation and an
independent host-side system-effect verifier.

The remaining risk is operational assembly. Requiring an operator to manually instantiate
staging, Docker supervisors, local model clients, the fixed Judge and the campaign runner
would reintroduce configuration drift at the final execution boundary.

At the same time, CI must never contact a Docker daemon or invoke a model.

## Decision

Add an explicit operator layer with two phases.

### Prepare

HalSmokeOperatorInputs contains only explicit local paths and identifiers:

- bounded model-role configuration;
- fresh saved OpenWebUI model inventory;
- exact Ollama artifact contracts;
- fresh saved local Ollama tags snapshot;
- digest-pinned runtime pins;
- local HAL Ollama models root;
- laboratory-owned Blue staging root;
- exact Blue manifest relative path;
- immutable workspace template;
- laboratory-owned disposable workspace root;
- budget configuration;
- Blue model ID.

prepare_hal_smoke_operator:

1. recreates the bounded static model plan;
2. validates local-only admission;
3. verifies exact artifact qualification;
4. composes the offline HAL runtime contract;
5. stages exactly the declared Blue manifest and referenced blobs;
6. requires the fresh staged-store identity to equal the predeclared runtime pins;
7. validates the fixed smoke budget profile;
8. constructs the disposable workspace supervisor.

This phase starts no Docker containers and performs no model inference.

### Execute

build_live_hal_smoke_runtime creates, but does not yet run:

- one shell-free Docker command runner;
- isolated model-network supervisor;
- staged Ollama peer supervisor;
- staged runtime artifact verifier;
- campaign-scoped Blue infrastructure supervisor;
- networked OpenCode AGENT supervisor;
- redacted OpenCode environment attestor;
- OpenCode health supervisor;
- composed OpenCode runtime supervisor;
- direct local Red OpenAI-compatible client;
- local Ollama tags probe;
- fixed SystemStateJudge and verifier policy;
- HalSmokeCampaignRunner.

run_live_hal_smoke then executes the fixed built-in smoke case and plan and closes the Red
runtime clients afterwards.

### Secret handling

The OpenCode server password remains an environment secret.

Before creating live runtime clients, the operator layer requires that the exact environment
variable named by the offline runtime profile is present and non-empty.

Only the variable name is part of stable configuration/evidence. The value is never logged,
hashed, serialized or persisted by the laboratory. Docker receives it through normal
environment-name inheritance.

### CLI

Add llm-redteam hal-smoke-run.

The command requires explicit local evidence/staging/workspace paths. It does not guess a
platform-specific Ollama cache or workspace directory.

Its result output is hash-safe and includes campaign/status, stable composition and staged
store identities, execution-provenance hashes, Blue infrastructure/teardown proof hashes,
cleanup status and campaign outcomes.

## Consequences

The repository now has one supported operator path from frozen local evidence to the first
real HAL smoke.

CI can exercise the prepare phase on a synthetic content-addressed Ollama store and exercise
runtime assembly without executing Docker commands. The CLI live boundary is tested with a
mocked final runner.

The next step is no longer architectural coding: the operator must collect fresh evidence
and execute this command on HAL. That is the point where actual local HAL access becomes
necessary.
