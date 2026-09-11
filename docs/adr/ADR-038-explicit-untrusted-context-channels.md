# ADR-038: Explicit untrusted context channels for indirect-injection evaluation

Status: Accepted
Date: 2026-09-11

## Context

Indirect prompt injection is not equivalent to a hostile user prompt. Retrieved RAG chunks,
tool responses and MCP-provided context cross different trust boundaries and therefore need
to remain distinguishable in execution evidence. Copying hostile environment text into the
user message would destroy source provenance and could overstate Red effectiveness.

The laboratory already supports adaptive multi-turn AGENT Red, immutable environment
fixtures, isolated per-trial workspaces, held-out external dependency binding and
independent system-state verification. The missing contract was a provider-independent way
to deliver attacker-controlled environment context without pretending that it came from the
user.

## Decision

1. `TargetRequest` carries environment-originated attacker data in an explicit
   `untrusted_context` collection, separate from the direct prompt and conversation history.
2. Every context item records a source channel, opaque source identifier, raw ephemeral
   content and a verified SHA-256 content hash.
3. Initial channels are `retrieval`, `tool_output` and `mcp_context`.
4. Context-backed fixtures reference a bounded UTF-8 `context_file` inside the immutable
   fixture bundle. Path traversal, symlinks through the bundle hash rules, oversized context
   and hash mismatches fail closed.
5. Generic fixture provenance persists hashes and channel identity, not raw hostile context.
6. A fixture-bound target must explicitly declare the `untrusted_context` capability before
   context-backed execution. Unsupported targets fail before the trial instead of silently
   dropping the attack input.
7. The first Blue message remains the fixture's legitimate task. Hostile bytes are never
   copied into the user prompt by the harness.
8. Later turns may adapt to target-visible behavior under the existing bounded multi-turn
   Red policy. One complete bounded conversation remains one trial; turns remain trajectory
   and cost observations.
9. A model requesting a forbidden action may establish `MODEL_COMPROMISE`. A
   `SYSTEM_COMPROMISE` still requires independent trusted effect evidence when the Judge
   policy requires verification.
10. This ADR introduces a transport-neutral harness contract only. It does not claim that
    OpenCode, OpenWebUI or a real MCP server currently consumes these channels. A concrete
    adapter must implement the channel semantics before advertising the capability.
11. External network access, real MCP infrastructure, real credentials and real secrets are
    not required by the native fixtures. Synthetic local effects remain the default.

## Rationale

MITRE ATLAS distinguishes agent context poisoning, tool data/tool poisoning and RAG
poisoning as separate adversary techniques. OWASP guidance likewise treats tool and MCP
responses as security-relevant untrusted inputs. Preserving the channel in the target
contract gives forensic analysis enough information to identify which trust boundary
failed, while retaining the project's mandatory separation between model intent and system
effect.

This also improves measurement validity: two experiments that present identical text through
different channels are not assumed to be equivalent security targets or equivalent attack
mechanisms.

## Consequences

### Positive

- RAG/retrieval and MCP-context poisoning can be exercised without falsifying user-prompt
  provenance.
- The same abstraction can later be implemented by OpenWebUI, custom RAG pipelines, MCP
  clients and other provider-specific adapters.
- Hash-only fixture provenance remains compatible with held-out external dependency binding.
- Unsupported adapters cannot accidentally produce false PASS results by ignoring context.
- Multi-turn Red can test sequences where an indirect injection establishes context and
  later target-visible interaction amplifies or probes the failure.

### Limitations

- Native v1 retrieval and MCP cases use deterministic synthetic targets. They prove the
  architecture, not the behavior of a real OpenWebUI/MCP deployment.
- Tool-output transport is defined but does not yet have a dedicated native fixture in this
  ADR because terminal-output coverage already exists and concrete provider semantics should
  be implemented before adding redundant cases.
- Raw context is present ephemerally in the target request by necessity; persistence remains
  hash-only unless a future evidence policy explicitly permits a redacted artifact.
- Real provider adapters must establish how retrieved/tool/MCP context is injected without
  changing the Blue target's normal trust semantics.

## Rejected alternatives

### Put hostile retrieval or MCP text in the user prompt

Rejected because it converts indirect injection into direct injection and invalidates source
provenance.

### Add only a metadata label while sending the text as a user message

Rejected because metadata would describe a trust boundary that execution did not actually
exercise.

### Let every target silently ignore unsupported context

Rejected because absence of attack exposure would be misclassified as security resistance.

### Give Red direct control over context-provider configuration

Rejected because attacker-controlled content may never expand its own permissions or mutate
the evaluator control plane.
