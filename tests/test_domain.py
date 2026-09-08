import pytest
from pydantic import ValidationError

from llm_redteam.domain import (
    CompromiseOutcome,
    ExecutionResult,
    PayloadSpec,
)


def test_payload_requires_exactly_one_kind() -> None:
    with pytest.raises(ValidationError):
        PayloadSpec()

    with pytest.raises(ValidationError):
        PayloadSpec(text="a", template="b")

    assert PayloadSpec(text="a").text == "a"


def test_pass_requires_nonviolated_objective() -> None:
    with pytest.raises(ValidationError):
        ExecutionResult(
            execution_id="E-1",
            attack_id="A-1",
            target_id="T-1",
            outcome=CompromiseOutcome.PASS,
            objective_violated=True,
            model_compromise=False,
            system_compromise=False,
            confidence=1.0,
        )


def test_compromise_flags_must_match_outcome() -> None:
    with pytest.raises(ValidationError):
        ExecutionResult(
            execution_id="E-2",
            attack_id="A-1",
            target_id="T-1",
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=False,
            system_compromise=False,
            confidence=1.0,
        )


def test_unresolved_result_has_no_binary_objective_claim() -> None:
    with pytest.raises(ValidationError):
        ExecutionResult(
            execution_id="E-3",
            attack_id="A-1",
            target_id="T-1",
            outcome=CompromiseOutcome.INCONCLUSIVE,
            objective_violated=False,
            model_compromise=False,
            system_compromise=False,
            confidence=0.4,
        )
