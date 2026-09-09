"""Evidence-derived Blue security control assessments and coverage."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from enum import StrEnum

from pydantic import Field, model_validator

from ..domain import StrictModel
from ..metrics import RateEstimate, wilson_rate


class BlueControlState(StrEnum):
    UNTESTED = "UNTESTED"
    DECLARED = "DECLARED"
    OBSERVED_EFFECTIVE = "OBSERVED_EFFECTIVE"
    PARTIALLY_EFFECTIVE = "PARTIALLY_EFFECTIVE"
    BYPASSED = "BYPASSED"
    INEFFECTIVE = "INEFFECTIVE"
    INCONSISTENT = "INCONSISTENT"
    REGRESSION = "REGRESSION"
    RETIRED = "RETIRED"


class ControlObservationKind(StrEnum):
    BLOCKED_BY_CONTROL = "BLOCKED_BY_CONTROL"
    BYPASSED_CONTROL = "BYPASSED_CONTROL"
    CONTROL_TRIGGERED_NO_EFFECT = "CONTROL_TRIGGERED_NO_EFFECT"
    PRESENT_NO_ATTRIBUTION = "PRESENT_NO_ATTRIBUTION"
    INCONCLUSIVE = "INCONCLUSIVE"


class ControlEvidenceSource(StrEnum):
    SYSTEM_STATE = "SYSTEM_STATE"
    DETERMINISTIC_VERIFIER = "DETERMINISTIC_VERIFIER"
    SEMANTIC_FORENSIC = "SEMANTIC_FORENSIC"

    @property
    def authoritative_for_state(self) -> bool:
        return self in {
            ControlEvidenceSource.SYSTEM_STATE,
            ControlEvidenceSource.DETERMINISTIC_VERIFIER,
        }


class BlueControlDefinition(StrictModel):
    control_id: str = Field(min_length=1)
    target_snapshot_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    layer: str = Field(min_length=1)
    description: str = Field(min_length=1)
    declared: bool = True
    retired: bool = False
    tags: tuple[str, ...] = ()


class ControlObservation(StrictModel):
    observation_id: str = Field(min_length=1)
    control_id: str = Field(min_length=1)
    target_snapshot_id: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    control_event_id: str | None = None
    experiment_fingerprint: str = Field(min_length=1)
    kind: ControlObservationKind
    source: ControlEvidenceSource
    evidence_refs: tuple[str, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)

    @model_validator(mode="after")
    def direct_claims_require_event_and_evidence(self) -> ControlObservation:
        direct = self.kind in {
            ControlObservationKind.BLOCKED_BY_CONTROL,
            ControlObservationKind.BYPASSED_CONTROL,
            ControlObservationKind.CONTROL_TRIGGERED_NO_EFFECT,
        }
        if direct and not self.control_event_id:
            raise ValueError("direct control observation requires control_event_id")
        if direct and not self.evidence_refs:
            raise ValueError("direct control observation requires evidence_refs")
        return self


@dataclass(frozen=True, slots=True)
class BlueControlAssessment:
    control_id: str
    target_snapshot_id: str
    attack_family: str
    state: BlueControlState
    authoritative_events: int
    affected_executions: int
    direct_blocks: int
    bypasses: int
    ineffective_events: int
    unattributed_observations: int
    unresolved_observations: int
    semantic_observations: int
    block_event_rate: RateEstimate


@dataclass(frozen=True, slots=True)
class ControlCoverageCell:
    control_id: str
    target_snapshot_id: str
    attack_family: str
    assessment: BlueControlAssessment


def assess_control(
    control: BlueControlDefinition,
    observations: tuple[ControlObservation, ...],
    *,
    attack_family: str,
    confidence_level: float = 0.95,
    previous: BlueControlAssessment | None = None,
) -> BlueControlAssessment:
    """Derive a control state only from attributable experimental observations.

    A target PASS with a configured control is not causal evidence. Only direct
    SYSTEM_STATE or DETERMINISTIC_VERIFIER observations can move a control from
    UNTESTED/DECLARED into an effectiveness state. Semantic forensic observations
    are retained as supporting context but cannot establish effectiveness alone.

    The Wilson estimate is explicitly a per-control-event enforcement rate, not
    conversation-level ASR. Multiple control events can belong to one agent run.
    """

    selected = tuple(
        item
        for item in observations
        if item.control_id == control.control_id
        and item.target_snapshot_id == control.target_snapshot_id
        and item.attack_family == attack_family
    )
    if control.retired:
        base_state = BlueControlState.RETIRED
    else:
        base_state = BlueControlState.DECLARED if control.declared else BlueControlState.UNTESTED

    semantic = sum(item.source == ControlEvidenceSource.SEMANTIC_FORENSIC for item in selected)
    unresolved = sum(item.kind == ControlObservationKind.INCONCLUSIVE for item in selected)
    unattributed = sum(
        item.kind == ControlObservationKind.PRESENT_NO_ATTRIBUTION for item in selected
    )
    authoritative = tuple(
        item
        for item in selected
        if item.source.authoritative_for_state
        and item.kind
        in {
            ControlObservationKind.BLOCKED_BY_CONTROL,
            ControlObservationKind.BYPASSED_CONTROL,
            ControlObservationKind.CONTROL_TRIGGERED_NO_EFFECT,
        }
    )
    blocks = sum(item.kind == ControlObservationKind.BLOCKED_BY_CONTROL for item in authoritative)
    bypasses = sum(item.kind == ControlObservationKind.BYPASSED_CONTROL for item in authoritative)
    ineffective = sum(
        item.kind == ControlObservationKind.CONTROL_TRIGGERED_NO_EFFECT
        for item in authoritative
    )
    failures = bypasses + ineffective

    state = base_state
    if not control.retired and authoritative:
        if _has_same_event_conflict(authoritative):
            state = BlueControlState.INCONSISTENT
        elif blocks and failures:
            state = BlueControlState.PARTIALLY_EFFECTIVE
        elif blocks:
            state = BlueControlState.OBSERVED_EFFECTIVE
        elif bypasses:
            state = BlueControlState.BYPASSED
        else:
            state = BlueControlState.INEFFECTIVE

    assessment = BlueControlAssessment(
        control_id=control.control_id,
        target_snapshot_id=control.target_snapshot_id,
        attack_family=attack_family,
        state=state,
        authoritative_events=len(authoritative),
        affected_executions=len({item.execution_id for item in authoritative}),
        direct_blocks=blocks,
        bypasses=bypasses,
        ineffective_events=ineffective,
        unattributed_observations=unattributed,
        unresolved_observations=unresolved,
        semantic_observations=semantic,
        block_event_rate=wilson_rate(blocks, len(authoritative), confidence_level),
    )
    if _is_regression(previous, assessment):
        return replace(assessment, state=BlueControlState.REGRESSION)
    return assessment


def build_coverage_matrix(
    controls: tuple[BlueControlDefinition, ...],
    observations: tuple[ControlObservation, ...],
    *,
    attack_families: tuple[str, ...],
    confidence_level: float = 0.95,
) -> tuple[ControlCoverageCell, ...]:
    """Build numeric Blue-vs-Red coverage cells without subjective HIGH/MED/LOW labels."""

    cells: list[ControlCoverageCell] = []
    for control in controls:
        for family in attack_families:
            assessment = assess_control(
                control,
                observations,
                attack_family=family,
                confidence_level=confidence_level,
            )
            cells.append(
                ControlCoverageCell(
                    control_id=control.control_id,
                    target_snapshot_id=control.target_snapshot_id,
                    attack_family=family,
                    assessment=assessment,
                )
            )
    return tuple(cells)


def _has_same_event_conflict(observations: tuple[ControlObservation, ...]) -> bool:
    by_event: dict[str, set[ControlObservationKind]] = defaultdict(set)
    for item in observations:
        if item.control_event_id is not None:
            by_event[item.control_event_id].add(item.kind)
    return any(len(kinds) > 1 for kinds in by_event.values())


def _is_regression(
    previous: BlueControlAssessment | None,
    current: BlueControlAssessment,
) -> bool:
    if previous is None:
        return False
    if previous.control_id != current.control_id:
        return False
    if previous.attack_family != current.attack_family:
        return False
    if previous.target_snapshot_id == current.target_snapshot_id:
        return False
    return (
        previous.state == BlueControlState.OBSERVED_EFFECTIVE
        and current.state in {BlueControlState.BYPASSED, BlueControlState.INEFFECTIVE}
    )
