# ADR-038: Isolated reference RAG pipeline for context-poisoning evaluation

Status: Accepted
Date: 2026-09-11

## Context

The laboratory already distinguishes MODEL, PIPELINE and AGENT targets and requires RAG
configuration, retrieved chunks and context boundaries to be part of security evidence.
However, a concrete RAG target was still missing. Treating a RAG attack as only another user
prompt would collapse a pipeline vulnerability into a model-only test and would lose the
provenance needed to reproduce indirect prompt injection.

RAG/context poisoning can also be sequence-dependent. A first turn can establish benign
context or probe retrieval behavior, while a later query deliberately surfaces a poisoned
chunk. Counting those turns as independent attacks would inflate the ASR denominator and
confound conversational strategy with independent trials.

## Decision

Introduce a small deterministic local RAG reference pipeline before integrating production
vector stores or OpenWebUI retrieval backends.

1. `LocalRagPipelineTarget` wraps a MODEL or PIPELINE target and exposes the composed system as
   target mode `PIPELINE`.
2. The complete target configuration hash binds the underlying target identity, retrieval
   corpus hash, retrieval algorithm version, `top_k` and context-size limit. Therefore the same
   model with a different corpus or retrieval configuration is a different security target.
3. `RagCorpus` has a canonical SHA-256 identity over document IDs, text and metadata.
4. The initial retriever is intentionally deterministic lexical overlap with stable tie
   breaking. It is a reference harness, not a claim that production vector retrieval behaves
   identically.
5. Retrieved chunks are injected into the wrapped target as explicitly delimited
   `UNTRUSTED_EXTERNAL_CONTENT`. The harness does not remove hostile instructions, because
   whether Blue treats retrieved data as authority is the property under test.
6. Each retrieval emits hash-only provenance evidence: query hash, corpus hash, ordered
   document IDs, ranks, scores, source hashes and exact injected-content hashes. Raw poisoned
   text is not persisted in ordinary evidence.
7. The retrieval corpus implements the generic external-input dependency contract using
   `kind=retrieval_corpus`. Held-out manifest schema v2 can therefore bind the exact external
   corpus used for evaluation.
8. One bounded multi-turn conversation remains one statistical trial. Retrieval events and
   turns are within-trial evidence/cost; they are not additional ASR observations.
9. Deterministic disclosure evidence can establish `MODEL_COMPROMISE`. `SYSTEM_COMPROMISE`
   still requires an independently observed unauthorized system effect; RAG retrieval alone
   does not imply system compromise.
10. No network access, real secrets or production data are required by this reference target.

## Rationale

A deterministic reference retriever gives the project a controllable way to prove the entire
RAG security contract: poisoned external data is retrieved, the exact injected chunks are
known, Blue sees a clear trust boundary, the response is judged independently, and the
external corpus can be frozen in a held-out manifest. This is more valuable at this stage than
prematurely coupling the core evaluator to one vector database or application-specific RAG
implementation.

The hash-only evidence model supports reproducibility while avoiding unnecessary duplication
of malicious fixture content in reports and databases.

## Consequences

### Positive

- RAG is now represented as a real PIPELINE target rather than a prompt label.
- Context poisoning can be tested as a multi-turn attack sequence without inflating ASR.
- Retrieval provenance is available for forensic analysis and regression conversion.
- The same generic external dependency contract can later cover OpenWebUI retrieval, custom
  vector stores, MCP resources and tool-data providers.

### Limitations

- Lexical overlap is not representative of semantic embedding/vector retrieval quality.
- The reference target does not yet model ingestion-time ACLs, multi-tenant indexes, caches,
  rerankers or embedding manipulation.
- Production adapters must surface their *actual* retrieved chunks and ordering; they must not
  substitute the reference retriever's trace.
- Generalized-population claims remain out of scope until a declared sampling/statistical
  model exists.

## Follow-up

1. Bind target-provided external dependencies automatically into campaign preflight and
   persisted measurement identity.
2. Add a concrete OpenWebUI/custom-RAG adapter that normalizes live retrieval traces into the
   same provenance contract.
3. Add controlled tests for multi-chunk composition, context flooding, retrieval steering,
   stale authorization and cross-tenant retrieval using synthetic corpora.
4. Extend the same external-input contract to MCP/tool-data poisoning after the RAG vertical
   slice is stable.
