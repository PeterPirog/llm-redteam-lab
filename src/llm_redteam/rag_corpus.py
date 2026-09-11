"""Local RAG corpus loading with strict schema validation."""

from __future__ import annotations

from pathlib import Path

import yaml

from .targets.rag import RagCorpus


def load_rag_corpus(path: str | Path) -> RagCorpus:
    """Load one local synthetic/reference RAG corpus and reject malformed content."""

    source = Path(path)
    if not source.is_file():
        raise ValueError(f"RAG corpus does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("RAG corpus root must be a mapping")
        normalized = {
            "corpus_id": raw.get("corpus_id"),
            "version": raw.get("version"),
            "documents": raw.get("documents"),
        }
        return RagCorpus.model_validate(normalized)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid RAG corpus {source}: {exc}") from exc
