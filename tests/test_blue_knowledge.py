from llm_redteam.blue import (
    BlueControlDefinition,
    BlueControlState,
    ControlEvidenceSource,
    ControlObservation,
    ControlObservationKind,
    assess_control,
    build_coverage_matrix,
)

SNAPSHOT = "target-snapshot-1"
FAMILY = "repository_prompt_injection"


def _control(*, snapshot: str = SNAPSHOT, declared: bool = True) -> BlueControlDefinition:
    return BlueControlDefinition(
        control_id="CTRL-REPO-PROVENANCE",
        target_snapshot_id=snapshot,
        name="repository_context_provenance",
        layer="context_boundary",
        description="Marks repository-derived context as untrusted data.",
        declared=declared,
    )


def _observation(
    observation_id: str,
    execution_id: str,
    kind: ControlObservationKind,
    *,
    source: ControlEvidenceSource = ControlEvidenceSource.SYSTEM_STATE,
    snapshot: str = SNAPSHOT,
) -> ControlObservation:
    return ControlObservation(
        observation_id=observation_id,
        control_id="CTRL-REPO-PROVENANCE",
        target_snapshot_id=snapshot,
        attack_family=FAMILY,
        execution_id=execution_id,
        experiment_fingerprint=f"fingerprint-{execution_id}",
        kind=kind,
        source=source,
        evidence_refs=(f"evidence-{execution_id}",),
    )


def test_declared_control_is_not_effective_without_attributed_evidence() -> None:
    assessment = assess_control(_control(), (), attack_family=FAMILY)

    assert assessment.state == BlueControlState.DECLARED
    assert assessment.authoritative_trials == 0
    assert assessment.block_rate.value is None


def test_semantic_forensics_alone_cannot_establish_control_effectiveness() -> None:
    observation = _observation(
        "obs-semantic",
        "exec-1",
        ControlObservationKind.BLOCKED_BY_CONTROL,
        source=ControlEvidenceSource.SEMANTIC_FORENSIC,
    )

    assessment = assess_control(_control(), (observation,), attack_family=FAMILY)

    assert assessment.state == BlueControlState.DECLARED
    assert assessment.semantic_observations == 1
    assert assessment.authoritative_trials == 0


def test_direct_system_state_block_establishes_observed_effectiveness() -> None:
    observation = _observation(
        "obs-block",
        "exec-1",
        ControlObservationKind.BLOCKED_BY_CONTROL,
    )

    assessment = assess_control(_control(), (observation,), attack_family=FAMILY)

    assert assessment.state == BlueControlState.OBSERVED_EFFECTIVE
    assert assessment.direct_blocks == 1
    assert assessment.block_rate.value == 1.0
    assert assessment.block_rate.trials == 1


def test_mixed_direct_blocks_and_bypasses_are_partially_effective() -> None:
    observations = (
        _observation("obs-block", "exec-1", ControlObservationKind.BLOCKED_BY_CONTROL),
        _observation("obs-bypass", "exec-2", ControlObservationKind.BYPASSED_CONTROL),
    )

    assessment = assess_control(_control(), observations, attack_family=FAMILY)

    assert assessment.state == BlueControlState.PARTIALLY_EFFECTIVE
    assert assessment.direct_blocks == 1
    assert assessment.bypasses == 1
    assert assessment.block_rate.value == 0.5


def test_same_execution_with_conflicting_direct_observations_is_inconsistent() -> None:
    observations = (
        _observation("obs-block", "exec-1", ControlObservationKind.BLOCKED_BY_CONTROL),
        _observation("obs-bypass", "exec-1", ControlObservationKind.BYPASSED_CONTROL),
    )

    assessment = assess_control(_control(), observations, attack_family=FAMILY)

    assert assessment.state == BlueControlState.INCONSISTENT


def test_bypass_and_no_effect_are_distinct_control_states() -> None:
    bypassed = assess_control(
        _control(),
        (_observation("obs-bypass", "exec-1", ControlObservationKind.BYPASSED_CONTROL),),
        attack_family=FAMILY,
    )
    ineffective = assess_control(
        _control(),
        (
            _observation(
                "obs-no-effect",
                "exec-2",
                ControlObservationKind.CONTROL_TRIGGERED_NO_EFFECT,
            ),
        ),
        attack_family=FAMILY,
    )

    assert bypassed.state == BlueControlState.BYPASSED
    assert ineffective.state == BlueControlState.INEFFECTIVE


def test_previous_effective_control_becoming_bypassed_is_regression() -> None:
    previous = assess_control(
        _control(snapshot="snapshot-v1"),
        (
            _observation(
                "obs-v1",
                "exec-v1",
                ControlObservationKind.BLOCKED_BY_CONTROL,
                snapshot="snapshot-v1",
            ),
        ),
        attack_family=FAMILY,
    )
    current = assess_control(
        _control(snapshot="snapshot-v2"),
        (
            _observation(
                "obs-v2",
                "exec-v2",
                ControlObservationKind.BYPASSED_CONTROL,
                snapshot="snapshot-v2",
            ),
        ),
        attack_family=FAMILY,
        previous=previous,
    )

    assert previous.state == BlueControlState.OBSERVED_EFFECTIVE
    assert current.state == BlueControlState.REGRESSION


def test_coverage_matrix_reports_numeric_evidence_not_subjective_labels() -> None:
    control = _control()
    observation = _observation(
        "obs-block",
        "exec-1",
        ControlObservationKind.BLOCKED_BY_CONTROL,
    )

    cells = build_coverage_matrix(
        (control,),
        (observation,),
        attack_families=(FAMILY, "tool_abuse"),
    )

    assert len(cells) == 2
    assert cells[0].assessment.state == BlueControlState.OBSERVED_EFFECTIVE
    assert cells[0].assessment.block_rate.trials == 1
    assert cells[1].assessment.state == BlueControlState.DECLARED
    assert cells[1].assessment.block_rate.value is None
