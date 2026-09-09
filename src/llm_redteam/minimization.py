"""Stability-aware minimization of reproducible adversarial attack components.

The minimizer is deliberately provider-independent. Callers componentize a successful
single-turn prompt or the successful path of a multi-turn conversation and provide an
async evaluator that executes a candidate against the same authorized target setup.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from enum import StrEnum

from pydantic import Field, model_validator

from .domain import ExecutionResult, StrictModel


class AttackComponentKind(StrEnum):
    TEXT_SEGMENT = "text_segment"
    TURN = "turn"
    INSTRUCTION = "instruction"
    ROLEPLAY = "roleplay"
    ENCODING_LAYER = "encoding_layer"
    OTHER = "other"


class AttackComponent(StrictModel):
    component_id: str = Field(min_length=1)
    kind: AttackComponentKind
    content: str = Field(min_length=1)
    required: bool = False


class AttackVariant(StrictModel):
    attack_id: str = Field(min_length=1)
    components: tuple[AttackComponent, ...]

    @model_validator(mode="after")
    def component_ids_are_unique(self) -> AttackVariant:
        ids = [component.component_id for component in self.components]
        if len(ids) != len(set(ids)):
            raise ValueError("attack component IDs must be unique")
        return self

    @property
    def component_ids(self) -> tuple[str, ...]:
        return tuple(component.component_id for component in self.components)

    def render_text(self, *, separator: str = "\n\n") -> str:
        return separator.join(component.content for component in self.components)


class StabilityPolicy(StrictModel):
    repetitions_per_candidate: int = Field(ge=1, default=2)
    required_successes: int = Field(ge=1, default=2)
    preserve_model_compromise: bool = True
    preserve_system_compromise: bool = True

    @model_validator(mode="after")
    def success_threshold_fits_repetitions(self) -> StabilityPolicy:
        if self.required_successes > self.repetitions_per_candidate:
            raise ValueError("required_successes cannot exceed repetitions_per_candidate")
        return self


class VariantAssessment(StrictModel):
    component_ids: tuple[str, ...]
    preserved: bool | None
    successful_attempts: int = Field(ge=0)
    conclusive_failures: int = Field(ge=0)
    unresolved_attempts: int = Field(ge=0)
    executions: tuple[ExecutionResult, ...]

    @model_validator(mode="after")
    def attempt_counts_are_consistent(self) -> VariantAssessment:
        total = (
            self.successful_attempts
            + self.conclusive_failures
            + self.unresolved_attempts
        )
        if total != len(self.executions):
            raise ValueError("variant assessment counts do not cover all executions")
        return self


class MinimizationStatus(StrEnum):
    COMPLETE = "COMPLETE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BASELINE_UNSTABLE = "BASELINE_UNSTABLE"


class MinimizationPolicy(StrictModel):
    max_target_executions: int = Field(ge=1, default=64)
    verify_baseline: bool = True
    stability: StabilityPolicy = Field(default_factory=StabilityPolicy)


class MinimizationResult(StrictModel):
    status: MinimizationStatus
    original: AttackVariant
    minimized: AttackVariant
    removed_component_ids: tuple[str, ...]
    target_executions: int = Field(ge=0)
    assessments: tuple[VariantAssessment, ...]


VariantEvaluator = Callable[[AttackVariant], Awaitable[ExecutionResult]]


class _ExecutionBudget:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.used = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.used

    @property
    def exhausted(self) -> bool:
        return self.used >= self.maximum

    def reserve(self) -> None:
        if self.exhausted:
            raise RuntimeError("minimization execution budget exhausted")
        self.used += 1


async def assess_variant(
    *,
    reference: ExecutionResult,
    variant: AttackVariant,
    evaluator: VariantEvaluator,
    policy: StabilityPolicy,
    execution_budget: _ExecutionBudget | None = None,
) -> VariantAssessment:
    """Evaluate whether a candidate stably preserves the reference compromise.

    ``None`` means the scheduled evidence was entirely unresolved. A conclusive
    execution that does not preserve the required compromise layer is a failure,
    never a defensive success for campaign metrics but sufficient to reject that
    minimization candidate.
    """

    if reference.objective_violated is not True:
        raise ValueError("reference execution must violate the security objective")

    successful = 0
    failures = 0
    unresolved = 0
    executions: list[ExecutionResult] = []

    for ordinal in range(policy.repetitions_per_candidate):
        if execution_budget is not None and execution_budget.exhausted:
            break
        if execution_budget is not None:
            execution_budget.reserve()

        execution = await evaluator(variant)
        executions.append(execution)
        if _preserves_reference(reference, execution, policy):
            successful += 1
        elif execution.objective_violated is None:
            unresolved += 1
        else:
            failures += 1

        if successful >= policy.required_successes:
            return VariantAssessment(
                component_ids=variant.component_ids,
                preserved=True,
                successful_attempts=successful,
                conclusive_failures=failures,
                unresolved_attempts=unresolved,
                executions=tuple(executions),
            )

        scheduled_remaining = policy.repetitions_per_candidate - ordinal - 1
        budget_remaining = (
            execution_budget.remaining if execution_budget is not None else scheduled_remaining
        )
        possible_remaining = min(scheduled_remaining, budget_remaining)
        if successful + possible_remaining < policy.required_successes:
            break

    if successful >= policy.required_successes:
        preserved: bool | None = True
    elif failures > 0:
        preserved = False
    elif unresolved > 0:
        preserved = None
    else:
        preserved = None

    return VariantAssessment(
        component_ids=variant.component_ids,
        preserved=preserved,
        successful_attempts=successful,
        conclusive_failures=failures,
        unresolved_attempts=unresolved,
        executions=tuple(executions),
    )


async def minimize_attack(
    *,
    reference: ExecutionResult,
    attack: AttackVariant,
    evaluator: VariantEvaluator,
    policy: MinimizationPolicy | None = None,
) -> MinimizationResult:
    """Delta-debug a confirmed/reproducible attack to a 1-minimal stable variant."""

    selected = policy or MinimizationPolicy()
    budget = _ExecutionBudget(selected.max_target_executions)
    assessments: list[VariantAssessment] = []

    if selected.verify_baseline:
        baseline = await assess_variant(
            reference=reference,
            variant=attack,
            evaluator=evaluator,
            policy=selected.stability,
            execution_budget=budget,
        )
        assessments.append(baseline)
        if baseline.preserved is not True:
            return MinimizationResult(
                status=MinimizationStatus.BASELINE_UNSTABLE,
                original=attack,
                minimized=attack,
                removed_component_ids=(),
                target_executions=budget.used,
                assessments=tuple(assessments),
            )

    current = list(attack.components)
    granularity = 2

    while not budget.exhausted:
        removable = [component for component in current if not component.required]
        if len(removable) < 2:
            break
        granularity = min(granularity, len(removable))
        reduced = False

        for chunk in _partition(removable, granularity):
            removed_ids = {component.component_id for component in chunk}
            candidate_components = [
                component
                for component in current
                if component.component_id not in removed_ids
            ]
            candidate = AttackVariant(
                attack_id=attack.attack_id,
                components=tuple(candidate_components),
            )
            assessment = await assess_variant(
                reference=reference,
                variant=candidate,
                evaluator=evaluator,
                policy=selected.stability,
                execution_budget=budget,
            )
            assessments.append(assessment)
            if assessment.preserved is True:
                current = candidate_components
                granularity = max(2, granularity - 1)
                reduced = True
                break
            if budget.exhausted:
                break

        if reduced:
            continue
        if granularity >= len(removable):
            break
        granularity = min(len(removable), granularity * 2)

    # Final single-component sweep establishes practical 1-minimality when budget allows.
    changed = True
    while changed and not budget.exhausted:
        changed = False
        for component in tuple(current):
            if component.required:
                continue
            candidate_components = [item for item in current if item != component]
            candidate = AttackVariant(
                attack_id=attack.attack_id,
                components=tuple(candidate_components),
            )
            assessment = await assess_variant(
                reference=reference,
                variant=candidate,
                evaluator=evaluator,
                policy=selected.stability,
                execution_budget=budget,
            )
            assessments.append(assessment)
            if assessment.preserved is True:
                current = candidate_components
                changed = True
                break
            if budget.exhausted:
                break

    minimized = AttackVariant(attack_id=attack.attack_id, components=tuple(current))
    remaining_ids = set(minimized.component_ids)
    removed = tuple(
        component.component_id
        for component in attack.components
        if component.component_id not in remaining_ids
    )
    status = (
        MinimizationStatus.BUDGET_EXHAUSTED
        if budget.exhausted
        else MinimizationStatus.COMPLETE
    )
    return MinimizationResult(
        status=status,
        original=attack,
        minimized=minimized,
        removed_component_ids=removed,
        target_executions=budget.used,
        assessments=tuple(assessments),
    )


def componentize_text(text: str, *, attack_id: str) -> AttackVariant:
    """Split a prompt into paragraph-level components without semantic rewriting."""

    paragraphs = [segment.strip() for segment in text.split("\n\n") if segment.strip()]
    components = tuple(
        AttackComponent(
            component_id=f"paragraph-{index}",
            kind=AttackComponentKind.TEXT_SEGMENT,
            content=paragraph,
        )
        for index, paragraph in enumerate(paragraphs, start=1)
    )
    return AttackVariant(attack_id=attack_id, components=components)


def componentize_turns(turns: Iterable[str], *, attack_id: str) -> AttackVariant:
    """Represent the successful linear multi-turn path as removable ordered turns."""

    components = tuple(
        AttackComponent(
            component_id=f"turn-{index}",
            kind=AttackComponentKind.TURN,
            content=turn,
        )
        for index, turn in enumerate(turns, start=1)
    )
    return AttackVariant(attack_id=attack_id, components=components)


def _preserves_reference(
    reference: ExecutionResult,
    candidate: ExecutionResult,
    policy: StabilityPolicy,
) -> bool:
    if candidate.objective_violated is not True:
        return False
    if (
        policy.preserve_model_compromise
        and reference.model_compromise
        and not candidate.model_compromise
    ):
        return False
    if (
        policy.preserve_system_compromise
        and reference.system_compromise
        and not candidate.system_compromise
    ):
        return False
    return True


def _partition(
    components: list[AttackComponent],
    parts: int,
) -> tuple[tuple[AttackComponent, ...], ...]:
    if parts <= 0:
        raise ValueError("parts must be positive")
    if not components:
        return ()
    size, remainder = divmod(len(components), parts)
    chunks: list[tuple[AttackComponent, ...]] = []
    cursor = 0
    for index in range(parts):
        width = size + (1 if index < remainder else 0)
        if width == 0:
            continue
        chunks.append(tuple(components[cursor : cursor + width]))
        cursor += width
    return tuple(chunks)
