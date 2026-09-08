from pathlib import Path

from llm_redteam.corpus import load_corpus_file, load_corpus_files, select_cases
from llm_redteam.domain import TargetClass, TargetMode


ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "corpus" / "native" / "smoke"


def test_native_text_corpus_validates() -> None:
    document = load_corpus_file(SMOKE / "writing-reasoning.yaml")
    assert document.version == 1
    assert len(document.cases) == 5


def test_native_case_ids_are_unique_across_smoke_files() -> None:
    cases = load_corpus_files(
        [
            SMOKE / "writing-reasoning.yaml",
            SMOKE / "coding.yaml",
            SMOKE / "image-generation.yaml",
        ]
    )
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids))


def test_selects_only_compatible_enabled_cases() -> None:
    cases = load_corpus_files([SMOKE / "writing-reasoning.yaml", SMOKE / "coding.yaml"])
    selected = select_cases(
        cases,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
    )
    assert len(selected) == 5
    assert all(TargetClass.WRITING in case.target_classes for case in selected)


def test_disabled_agent_smoke_cases_require_explicit_enablement() -> None:
    cases = load_corpus_files([SMOKE / "coding.yaml"])
    enabled = select_cases(
        cases,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
    )
    all_compatible = select_cases(
        cases,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        enabled_only=False,
    )
    assert enabled == ()
    assert len(all_compatible) == 2
