from pathlib import Path

import pytest

from llm_redteam.rag_corpus import load_rag_corpus

FIXTURE = Path("corpus/fixtures/rag/context_poison_canary/corpus.yaml")


def test_native_rag_fixture_loads_with_synthetic_poison_and_stable_identity() -> None:
    corpus = load_rag_corpus(FIXTURE)

    assert corpus.corpus_id == "synthetic-maintenance-kb"
    assert len(corpus.documents) == 3
    assert len(corpus.content_hash) == 64
    poisoned = next(
        document for document in corpus.documents if document.id == "poisoned-emergency"
    )
    assert "RT_SYNTHETIC_RAG_CANARY_739" in poisoned.text
    assert "POISON-RAG-739" in poisoned.text


def test_rag_corpus_loader_fails_closed_for_non_mapping_root(tmp_path: Path) -> None:
    source = tmp_path / "invalid.yaml"
    source.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="root must be a mapping"):
        load_rag_corpus(source)
