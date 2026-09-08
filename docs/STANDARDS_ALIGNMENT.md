# Standards Alignment

Last verified: 2026-09-08

`llm-redteam-lab` uses external standards as classification and governance crosswalks, not as substitutes for experimental evidence.

## OWASP GenAI Security Project

Primary reference: **OWASP GenAI LLM Top 10 2026** (released August 2026).

- https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/

The project should map relevant findings to the current OWASP risk identifiers when the mapping is defensible. Mappings are metadata; an OWASP label does not prove exploitation.

For AGENT targets, also use the **OWASP Agent Control Standard (ACS)** (released September 2026):

- https://genai.owasp.org/resource/agent-control-standard-acs/

ACS is particularly relevant to runtime inspection, traceability, middleware enforcement, portable policy controls and authorization boundaries. `llm-redteam-lab` should therefore preserve tool-request, authorization and execution evidence as separate events.

## MITRE ATLAS

Primary reference:

- https://atlas.mitre.org/

ATLAS is a living knowledge base and currently includes Generative AI and Agentic AI techniques. Findings should be mapped by technique name/identifier using the version observed at report generation time.

High-value mappings for this project include concepts such as:

- LLM Prompt Injection,
- LLM Jailbreak,
- AI Agent Context Poisoning,
- AI Agent Tool Data Poisoning,
- AI Agent Tool Poisoning,
- AI Agent Tool Invocation,
- Escape to Host,
- Retrieval Content Crafting.

Because ATLAS evolves, technique IDs/names must not be duplicated as immutable business logic. Store the external ID/name and a `verified_at` timestamp with the finding/report.

## NIST AI RMF and Generative AI Profile

Primary references:

- NIST AI RMF 1.0
- NIST AI 600-1, *Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile*
- https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence

NIST alignment is used primarily for risk-management and measurement discipline. Reports should make uncertainty explicit and separate:

- observed evidence,
- statistical estimates,
- assumptions,
- unresolved cases,
- risk interpretation,
- recommended mitigations.

A benchmark result with few trials must never be presented as a precise population-level property of a model.

## OpenTelemetry

Primary references:

- OpenTelemetry semantic conventions 1.44.0
- OpenTelemetry GenAI semantic conventions
- https://opentelemetry.io/docs/specs/semconv/

GenAI semantic conventions are evolving and have moved to a dedicated OpenTelemetry GenAI repository. The project should therefore:

1. use standard `gen_ai.*` attributes when stable/appropriate,
2. keep project-specific security attributes under a separate namespace such as `llm_redteam.*`,
3. record the semantic-convention version/configuration,
4. treat prompt/content attributes as sensitive and opt-in,
5. prefer content hashes/artifact references in normal telemetry rather than raw secrets or unrestricted prompts.

Useful GenAI concepts include `gen_ai.operation.name`, model/provider identity, token usage, agent identity and tool execution.

## Evidence before taxonomy

Standards crosswalks are downstream of judgment:

```text
execution
  -> evidence
  -> deterministic/system-state/semantic judgment
  -> MODEL_COMPROMISE / SYSTEM_COMPROMISE
  -> reproducibility
  -> finding
  -> standards mappings
```

Do not reverse this dependency. A test being categorized as "prompt injection" does not imply that the target was compromised.

## Versioning policy

Each generated report should record:

- framework version,
- corpus version,
- target configuration hash,
- standards mapping version or verification date,
- OpenTelemetry semantic-convention configuration,
- metric definition version.

This enables later reinterpretation when external standards change without rewriting historical experimental evidence.
