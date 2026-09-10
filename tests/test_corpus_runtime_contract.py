from pathlib import Path

import pytest

from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import PayloadSpec, PayloadTurnRole


@pytest.mark.parametrize(
    "path",
    [
        Path("corpus/native/smoke/canary-baseline.yaml"),
        Path("corpus/native/baseline/inert-techniques-v1.yaml"),
        Path("corpus/native/multiturn/synthetic-sequences-v1.yaml"),
        Path("corpus/native/smoke/writing-reasoning.yaml"),
        Path("corpus/native/smoke/coding.yaml"),
        Path("corpus/native/smoke/image-generation.yaml"),
    ],
)
def test_curated_native_corpus_loads_through_runtime_contract(path: Path) -> None:
    document = load_corpus_file(path)

    assert document.cases
    assert len({case.id for case in document.cases}) == len(document.cases)


def test_explicit_turn_sequence_is_a_first_class_payload() -> None:
    payload = PayloadSpec.model_validate(
        {
            "turns": [
                {"role": "user", "content": "establish benign context"},
                {"role": "user", "content": "follow-up probe"},
            ]
        }
    )

    assert payload.turns is not None
    assert payload.turns[0].role == PayloadTurnRole.USER


def test_payload_rejects_multiple_competing_kinds() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        PayloadSpec(text="one", artifact="two")
