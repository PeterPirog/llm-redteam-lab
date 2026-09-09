"""Counterfactual replay for evidence-backed attack component analysis.

This module evaluates removal and singleton variants of an already successful attack.
It estimates conditional necessity/sufficiency under the tested target configuration;
it does not claim universal or formal causality beyond the performed interventions.
"""

from __future__ import annotations

from pydantic import Field

from .domain import ExecutionResult, StrictModel
from .minimization import (
    AttackVariant,
    StabilityPolicy,
    VariantAssessment,
    VariantEvaluator,
    assess_variant,
)


class CounterfactualPolicy(StrictModel):
    max_counterfactual_variants: int = Field(ge=1, default=32)
    evaluate_leave_one_out: bool = True
    evaluate_singletons: bool = True
    evaluate_empty_baseline: bool = True
    stability: StabilityPolicy = Field(default_factory=StabilityPolicy)


class ComponentCounterfactual(StrictModel):
    component_id: str = Field(min_length=1)
    without_component: VariantAssessment | None = None
    component_alone: VariantAssessment | None = None
    necessary_under_test: bool | None = None
    sufficient_under_test: bool | None = None


class CounterfactualResult(StrictModel):
    attack_id: str = Field(min_length=1)
    component_results: tuple[ComponentCounterfactual, ...]
    empty_baseline: VariantAssessment | None = None
    evaluated_variants: int = Field(ge=0)
    target_executions: int = Field(ge=0)
    truncated_by_budget: bool = False


async def analyze_counterfactuals(
    *,
    reference: ExecutionResult,
    attack: AttackVariant,
    evaluator: VariantEvaluator,
    policy: CounterfactualPolicy | None = None,
) -> CounterfactualResult:
    """Evaluate component necessity/sufficiency using bounded replay experiments."""

    selected = policy or CounterfactualPolicy()
    component_rows: list[ComponentCounterfactual] = []
    evaluated_variants = 0
    target_executions = 0
    truncated = False

    async def run_variant(variant: AttackVariant) -> VariantAssessment | None:
        nonlocal evaluated_variants, target_executions, truncated
        if evaluated_variants >= selected.max_counterfactual_variants:
            truncated = True
            return None
        assessment = await assess_variant(
            reference=reference,
            variant=variant,
            evaluator=evaluator,
            policy=selected.stability,
        )
        evaluated_variants += 1
        target_executions += len(assessment.executions)
        return assessment

    empty_baseline: VariantAssessment | None = None
    if selected.evaluate_empty_baseline:
        empty_baseline = await run_variant(
            AttackVariant(attack_id=attack.attack_id, components=())
        )

    for component in attack.components:
        without: VariantAssessment | None = None
        alone: VariantAssessment | None = None

        if selected.evaluate_leave_one_out:
            without = await run_variant(
                AttackVariant(
                    attack_id=attack.attack_id,
                    components=tuple(
                        item
                        for item in attack.components
                        if item.component_id != component.component_id
                    ),
                )
            )

        if selected.evaluate_singletons:
            alone = await run_variant(
                AttackVariant(
                    attack_id=attack.attack_id,
                    components=(component,),
                )
            )

        component_rows.append(
            ComponentCounterfactual(
                component_id=component.component_id,
                without_component=without,
                component_alone=alone,
                necessary_under_test=_necessity(without),
                sufficient_under_test=_sufficiency(alone),
            )
        )

    return CounterfactualResult(
        attack_id=attack.attack_id,
        component_results=tuple(component_rows),
        empty_baseline=empty_baseline,
        evaluated_variants=evaluated_variants,
        target_executions=target_executions,
        truncated_by_budget=truncated,
    )


def _necessity(assessment: VariantAssessment | None) -> bool | None:
    if assessment is None:
        return None
    if assessment.preserved is True:
        return False
    if assessment.preserved is None or assessment.unresolved_attempts:
        return None
    return True


def _sufficiency(assessment: VariantAssessment | None) -> bool | None:
    if assessment is None:
        return None
    if assessment.preserved is True:
        return True
    if assessment.preserved is None or assessment.unresolved_attempts:
        return None
    return False
