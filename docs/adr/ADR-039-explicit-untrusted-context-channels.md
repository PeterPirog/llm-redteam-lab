# ADR-039: Explicit untrusted context channels for agentic indirect injection

Status: Accepted
Date: 2026-09-11

## Context

PR #39 / ADR-038 established a deterministic RAG `PIPELINE` reference target whose
retrieval corpus is part of target identity and held-out dependency provenance. Agentic
systems introduce a related but different boundary: retrieval results, tool output and MCP
context may be delivered by the agent runtime itself rather than by a harness-owned RAG
pipeline.

Treating that environment-originated content as a hostile user message would convert an
indirect injection into a direct injection and erase the evidence needed to identify which
trust boundary failed. The laboratory therefore needs a transport-neutral request contract
for target adapters that natively consume external context.

## Decision

1. `TargetRequest` has a separate `untrusted_context` collection for environment-originated
   attacker data. It is not part of the direct user prompt or replayed user conversation.
2. Each item records an explicit channel (`retrieval`, `tool_output`, or `mcp_context`), an
   opaque source identifier, ephemeral raw content and a verified SHA-256 content hash.
3. Immutable fixture manifests may bind a bounded UTF-8 `context_file` for those channels.
   Path traversal, missing files, empty content, oversized content and hash changes between
   describe/prepare fail closed.
4. Generic fixture provenance persists channel identity and hashes, not raw hostile context.
5. A context-backed fixture may run only against a target whose immutable identity declares
   the `untrusted_context` capability. The fixture wrapper rejects unsupported targets before
   target execution rather than allowing a false PASS caused by dropped input.
6. The first Blue interaction remains the fixture's legitimate task. Hostile MCP/tool
   context is never copied into that user prompt by the evaluator.
7. Later turns may adapt to target-visible Blue behavior under the existing bounded
   multi-turn Red runtime. One complete bounded conversation remains one trial; individual
   turns remain trajectory and resource-cost observations.
8. A forbidden action request can establish `MODEL_COMPROMISE`. `SYSTEM_COMPROMISE` remains
   dependent on independent trusted system-effect evidence under the Judge policy.
9. The native v1 MCP fixture is local, inert and synthetic. It proves the lifecycle and trust
   boundary without requiring a live MCP server, external network, real credentials or real
   secrets.
10. Concrete OpenCode/OpenWebUI/MCP adapters must implement the actual context transport
    before advertising `untrusted_context`. Adding only the capability flag is invalid.
11. The RAG reference pipeline from ADR-038 remains the canonical deterministic PIPELINE
    RAG harness. This ADR does not introduce a competing RAG implementation.

## Rationale

MITRE ATLAS distinguishes `AI Agent Context Poisoning`, `AI Agent Tool Data Poisoning`,
`AI Agent Tool Poisoning` and `RAG Poisoning`. OWASP MCP guidance likewise treats MCP/tool
responses as security-relevant untrusted inputs. A channel-preserving contract therefore
improves both attack realism and forensic explanation compared with flattening all content
into one prompt string.

The contract also protects measurement validity: identical hostile text arriving through a
user prompt, a retriever, a tool result or MCP context is not assumed to exercise the same
security boundary.

## Consequences

### Positive

- MCP/tool-context poisoning becomes an executable adaptive AGENT attack surface.
- Context provenance survives into hash-only evidence and attack genealogy.
- Unsupported targets fail before inference instead of being credited with resistance to an
  attack they never received.
- Multi-turn Red can test accumulation: environment context can establish the initial state,
  while subsequent target-visible turns probe whether the trust-boundary failure compounds.
- The design composes with held-out external-input binding and existing fixture isolation.

### Limitations

- The native MCP target is deterministic and synthetic; it proves architecture, not a real
  MCP client's security posture.
- Production adapter support remains a separate milestone and must preserve the application's
  real trust semantics.
- The `tool_output` channel is part of the contract, but terminal-output fixture coverage
  already exists and a provider-specific tool transport should be proven before adding a
  redundant generic fixture.
- Raw context exists ephemerally in the target request because the target must consume it;
  normal persisted evidence remains hash-only.

## Rejected alternatives

### Copy hostile MCP text into the user prompt

Rejected because it destroys indirect-injection provenance and measures the wrong boundary.

### Reuse ADR-038 or add a second RAG wrapper

Rejected because ADR-038 already defines the isolated RAG `PIPELINE` vertical slice. A
second implementation would create architectural drift and ambiguous target identity.

### Allow unsupported targets to ignore context

Rejected because no exposure is not evidence of security resistance.

### Let Red mutate MCP configuration or grant itself tools

Rejected because attacker-controlled content may never expand its own permissions or modify
the evaluator control plane.
