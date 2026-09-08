"""Load and validate normalized attack corpus documents."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from .domain import AttackCase, CorpusDocument, TargetClass, TargetMode


class CorpusValidationError(ValueError):
    """Raised when a corpus file cannot be normalized safely."""


def load_corpus_file(path: str | Path) -> CorpusDocument:
    """Load a YAML corpus file and validate it with the strict Pydantic model."""

    source = Path(path)
    if not source.is_file():
        raise CorpusValidationError(f"corpus file does not exist: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
        return CorpusDocument.model_validate(data)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise CorpusValidationError(f"invalid corpus file {source}: {exc}") from exc


def load_corpus_files(paths: Iterable[str | Path]) -> tuple[AttackCase, ...]:
    """Load several corpus documents and enforce globally unique case IDs."""

    cases: list[AttackCase] = []
    seen: set[str] = set()
    for path in paths:
        document = load_corpus_file(path)
        for case in document.cases:
            if case.id in seen:
                message = f"duplicate attack case ID across corpus files: {case.id}"
                raise CorpusValidationError(message)
            seen.add(case.id)
            cases.append(case)
    return tuple(cases)


def select_cases(
    cases: Iterable[AttackCase],
    *,
    target_class: TargetClass,
    target_mode: TargetMode,
    enabled_only: bool = True,
) -> tuple[AttackCase, ...]:
    """Select cases compatible with a concrete Blue target."""

    return tuple(
        case
        for case in cases
        if target_class in case.target_classes
        and target_mode in case.target_modes
        and (case.enabled_by_default or not enabled_only)
    )
