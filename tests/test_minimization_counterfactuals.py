import asyncio

from llm_redteam.counterfactuals import CounterfactualPolicy, analyze_counterfactuals
from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.minimization import (
    AttackComponent,
    AttackComponentKind,
    AttackVariant,
    MinimizationPolicy,
    MinimizationStatus,
    StabilityPolicy,
    componentize_text,
    componentize_turns,
    minimize_attack,
)


def _execution(
    execution_id: str,
    *,
    violated: bool | None,
    model: bool = False,
    system: bool = False,
) -> ExecutionResult:
    if violated is None:
        return ExecutionResult(
            execution_id=execution_id,
            attack_id="attack-1",
            target_id="target-1",
            outcome=CompromiseOutcome.INCONCLUSIVE,
            objective_violated=None,
            model_compromise=False,
            system_compromise=False,
            confidence=0.0,
        )
    if violated and model and system:
        outcome = CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE
    elif violated and model:
        outcome = CompromiseOutcome.MODEL_COMPROMISE
    elif violated and system:
        outcome = CompromiseOutcome.SYSTEM_COMPROMISE
    else:
        outcome = CompromiseOutcome.PASS
    return ExecutionResult(
        execution_id=execution_id,
        attack_id="attack-1",
        target_id="target-1",
        outcome=outcome,
        objective_violated=violated,
        model_compromise=model,
        system_compromise=system,
        confidence=1.0,
    )


def _variant(*ids: str) -> AttackVariant:
    return AttackVariant(
        attack_id="attack-1",
        components=tuple(
            AttackComponent(
                component_id=component_id,
                kind=AttackComponentKind.TEXT_SEGMENT,
                content=f"synthetic component {component_id}",
            )
            for component_id in ids
        ),
    )


def _stable_policy() -> StabilityPolicy:
    return StabilityPolicy(repetitions_per_candidate=2, required_successes=2)


def test_componentize_text_preserves_paragraph_order() -> None:
    attack = componentize_text("alpha\n\nbeta\n\ngamma", attack_id="attack-1")

    assert attack.component_ids == ("paragraph-1", "paragraph-2", "paragraph-3")
    assert attack.render_text() == "alpha\n\nbeta\n\ngamma"


def test_minimizer_removes_irrelevant_component_and_keeps_joint_cause() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = _variant("a", "b", "c")
    counter = 0

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        nonlocal counter
        counter += 1
        ids = set(candidate.component_ids)
        success = {"a", "c"}.issubset(ids)
        return _execution(f"candidate-{counter}", violated=success, model=success)

    result = asyncio.run(
        minimize_attack(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=MinimizationPolicy(
                max_target_executions=32,
                stability=_stable_policy(),
            ),
        )
    )

    assert result.status == MinimizationStatus.COMPLETE
    assert result.minimized.component_ids == ("a", "c")
    assert result.removed_component_ids == ("b",)
    assert result.target_executions >= 2


def test_minimizer_never_removes_required_component() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = AttackVariant(
        attack_id="attack-1",
        components=(
            AttackComponent(
                component_id="required-context",
                kind=AttackComponentKind.INSTRUCTION,
                content="synthetic required context",
                required=True,
            ),
            AttackComponent(
                component_id="cause",
                kind=AttackComponentKind.TEXT_SEGMENT,
                content="synthetic causal component",
            ),
            AttackComponent(
                component_id="noise",
                kind=AttackComponentKind.TEXT_SEGMENT,
                content="synthetic noise",
            ),
        ),
    )

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        success = "cause" in candidate.component_ids
        return _execution("candidate", violated=success, model=success)

    result = asyncio.run(
        minimize_attack(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=MinimizationPolicy(stability=_stable_policy()),
        )
    )

    assert "required-context" in result.minimized.component_ids
    assert "cause" in result.minimized.component_ids
    assert "noise" not in result.minimized.component_ids


def test_unresolved_reduction_is_not_accepted_as_evidence_of_irrelevance() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = _variant("a", "b")

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        if candidate.component_ids == ("a",):
            return _execution("uncertain", violated=None)
        success = {"a", "b"}.issubset(set(candidate.component_ids))
        return _execution("candidate", violated=success, model=success)

    result = asyncio.run(
        minimize_attack(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=MinimizationPolicy(stability=_stable_policy()),
        )
    )

    assert result.minimized.component_ids == ("a", "b")
    assert any(assessment.preserved is None for assessment in result.assessments)


def test_system_compromise_minimization_must_preserve_system_layer() -> None:
    reference = _execution("reference", violated=True, model=True, system=True)
    attack = _variant("model-cause", "system-cause")

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        ids = set(candidate.component_ids)
        if "model-cause" not in ids:
            return _execution("pass", violated=False)
        if "system-cause" not in ids:
            return _execution("model-only", violated=True, model=True, system=False)
        return _execution("full", violated=True, model=True, system=True)

    result = asyncio.run(
        minimize_attack(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=MinimizationPolicy(stability=_stable_policy()),
        )
    )

    assert result.minimized.component_ids == ("model-cause", "system-cause")


def test_multi_turn_minimization_preserves_order_and_removes_redundant_turn() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = componentize_turns(
        ("synthetic primer", "synthetic redundant turn", "synthetic finisher"),
        attack_id="attack-1",
    )

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        contents = tuple(component.content for component in candidate.components)
        success = contents == ("synthetic primer", "synthetic finisher") or contents == (
            "synthetic primer",
            "synthetic redundant turn",
            "synthetic finisher",
        )
        return _execution("candidate", violated=success, model=success)

    result = asyncio.run(
        minimize_attack(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=MinimizationPolicy(stability=_stable_policy()),
        )
    )

    assert tuple(component.content for component in result.minimized.components) == (
        "synthetic primer",
        "synthetic finisher",
    )


def test_counterfactuals_identify_conditional_necessity_without_overclaiming() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = _variant("a", "b", "c")
    counter = 0

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        nonlocal counter
        counter += 1
        success = {"a", "c"}.issubset(set(candidate.component_ids))
        return _execution(f"cf-{counter}", violated=success, model=success)

    result = asyncio.run(
        analyze_counterfactuals(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=CounterfactualPolicy(stability=_stable_policy()),
        )
    )
    by_id = {row.component_id: row for row in result.component_results}

    assert by_id["a"].necessary_under_test is True
    assert by_id["b"].necessary_under_test is False
    assert by_id["c"].necessary_under_test is True
    assert by_id["a"].sufficient_under_test is False
    assert by_id["b"].sufficient_under_test is False
    assert by_id["c"].sufficient_under_test is False
    assert result.empty_baseline is not None
    assert result.empty_baseline.preserved is False


def test_counterfactual_unresolved_removal_produces_unknown_necessity() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = _variant("a", "b")

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        if candidate.component_ids == ("a",):
            return _execution("uncertain", violated=None)
        success = "a" in candidate.component_ids
        return _execution("candidate", violated=success, model=success)

    result = asyncio.run(
        analyze_counterfactuals(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=CounterfactualPolicy(stability=_stable_policy()),
        )
    )
    by_id = {row.component_id: row for row in result.component_results}

    assert by_id["b"].necessary_under_test is None


def test_counterfactual_budget_truncates_without_inventing_results() -> None:
    reference = _execution("reference", violated=True, model=True)
    attack = _variant("a", "b", "c")

    async def evaluator(candidate: AttackVariant) -> ExecutionResult:
        success = "a" in candidate.component_ids
        return _execution("candidate", violated=success, model=success)

    result = asyncio.run(
        analyze_counterfactuals(
            reference=reference,
            attack=attack,
            evaluator=evaluator,
            policy=CounterfactualPolicy(
                max_counterfactual_variants=2,
                stability=StabilityPolicy(
                    repetitions_per_candidate=1,
                    required_successes=1,
                ),
            ),
        )
    )

    assert result.truncated_by_budget is True
    assert result.evaluated_variants == 2
    assert result.target_executions == 2
    assert any(
        row.without_component is None or row.component_alone is None
        for row in result.component_results
    )
