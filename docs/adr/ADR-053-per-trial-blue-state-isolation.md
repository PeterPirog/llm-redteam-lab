# ADR-053: Per-trial Blue state isolation for comparative attacker experiments

- Status: Accepted
- Date: 2026-09-12

## Context

ADR-049/050 introduced a fixed multi-attacker measurement contract and explicit runtime
routing. ADR-051 persisted the full-cross `attacker × case × replicate` execution schedule,
and ADR-052 added the explicit attacker-pool campaign lifecycle. Those controls prevent
outcome-driven assignment, but they do not by themselves prove that each attacker observes
the same initial Blue state.

This matters because a bounded jailbreak trial can change state outside the visible
conversation transcript:

- target-managed session memory;
- pipeline caches, RAG/application memory, middleware state or tool state;
- agent workspaces, repositories, shell state, MCP state, local files and process state.

`SessionMode.REPLAY` only controls how conversation history is supplied. It does not reset
those external state surfaces. Reusing a mutated Blue environment can therefore create
order effects and contaminate attacker comparisons.

Current external guidance reinforces this boundary. OWASP Agent Control Standard (2026)
requires agent systems to be inspectable, traceable, instrumentable and controllable at
runtime. OWASP APTS requires containment and audit controls that do not depend on the
agent runtime's cooperation. MITRE ATLAS now explicitly models agent context poisoning,
tool-data poisoning and tool poisoning. NIST AI 800-3 emphasizes explicit measurement
targets and assumptions rather than conflating distinct evaluation conditions.

## Decision

Introduce a trusted `TargetTrialLeaseProvider` boundary outside Red and outside Blue.

A lease contains:

- an ephemeral `TargetAdapter` for the trial;
- a hash-only `TargetTrialIsolationAttestation`;
- an isolation level;
- a provider fingerprint;
- a fresh-state proof hash bound to the Blue configuration.

The provider must also produce a teardown result after the trial. Acquisition and release
facts are persisted independently from ordinary execution rows so they survive target or
transport failure.

### Isolation strength

The minimum isolation boundary depends on target mode, not only conversation mode:

| Target / session | Minimum boundary |
| --- | --- |
| `MODEL + REPLAY` | no lease required by this contract |
| `MODEL + TARGET_MANAGED` | fresh session namespace |
| `PIPELINE` (either session mode) | fresh application instance |
| `AGENT` (either session mode) | disposable sandbox |

The ordering is monotonic:

`SESSION_NAMESPACE < APPLICATION_INSTANCE < DISPOSABLE_SANDBOX`.

A stronger attestation may satisfy a weaker requirement. A weaker attestation fails closed.

### Transcript isolation is not system isolation

`REPLAY` remains useful and reproducible, but it must not be interpreted as proof that a
pipeline or agent has clean non-transcript state. This ADR explicitly separates those two
concepts.

### Control-plane independence

The attestation must state that isolation is enforced independently from Blue. Red/Blue
content may not create, strengthen, weaken, replace or approve its own lease.

For real AGENT targets, the intended implementation is a supervisor-backed disposable
sandbox attestation (for example the existing Docker supervisor/attestation primitives),
not a prompt-level reset request.

### In-memory provider

`InMemoryFreshTargetLeaseProvider` exists only for deterministic/memory-resident tests
where all mutable state is contained in the target object. It refuses to claim
`DISPOSABLE_SANDBOX` strength and must not be used as evidence for externally backed
applications or agents.

### Failure semantics

The full-cross assignment is persisted before lease acquisition and target execution.
Therefore:

- failed acquisition leaves the declared opportunity visible;
- successful acquisition is persisted before Blue is called;
- teardown is attempted in `finally`;
- teardown proof is persisted even if target execution crashes;
- incomplete cleanup is a hard failure, not a successful defense result;
- an interrupted trial remains allocated/incomplete rather than silently disappearing.

One bounded conversation still equals one statistical security trial.

## Consequences

### Positive

- reduces attacker-order and residual-state confounding;
- makes target-managed multi-attacker tests executable without sharing session state;
- creates a provider-independent path to isolated OpenWebUI/OpenCode campaigns;
- preserves the distinction between transcript, application and sandbox state;
- strengthens forensic evidence around containment and teardown.

### Costs

- pipeline and agent pool campaigns now require a concrete isolation provider;
- fixture-backed AGENT pool execution still needs a compound fixture + target lease
  integration before it can be enabled;
- real OpenCode execution still needs a Docker-backed lease implementation and narrowly
  scoped local model connectivity.

## Non-decisions

This ADR does not:

- define the final Docker/Ollama network topology;
- claim that an in-memory fresh Python object proves external application isolation;
- change ASR/MCR/SCR estimands;
- allow Red to inspect Judge verdicts during live adaptation;
- make a model compromise equivalent to a system compromise.
