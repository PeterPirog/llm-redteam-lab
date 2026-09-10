"""Provider-independent execution harness for paired Red component ablations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..domain import AttackCase
from ..evaluation_protocol import MeasurementProtocol
from ..evaluation_sets import HeldOutEvaluationManifest, select_manifest_cases
from .ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedAblationReport,
    PairedRedObservation,
    PairedTrialPlan,
    PairingMode,
    build_counterbalanced_pair_plan,
    summarize_paired_red_ablation,
)


@runtime_checkable
class PairedTrialExecutor(Protocol):
    """Execute one arm of one bounded case/replicate pair.

    Implementations may use MODEL, PIPELINE or AGENT targets. They are responsible
    for creating/resetting the target and Red strategy for the requested trial and
    for returning a resource-accounted observation. The harness owns pairing/order,
    not target permissions or attack generation.
    """

    async def __call__(
        self,
        arm: AblationArm,
        case: AttackCase,
        replicate: int,
        pair_seed: int | None,
    ) -> PairedRedObservation: ...


@dataclass(frozen=True, slots=True)
class PairedRedAblationExecution:
    """Complete execution artifact needed for reporting and immutable persistence."""

    plan: tuple[PairedTrialPlan, ...]
    observations: tuple[PairedRedObservation, ...]
    report: PairedRedAblationReport


async def execute_paired_red_ablation_with_observations(
    *,
    cases: Iterable[AttackCase],
    contract: PairedRedAblationContract,
    manifest: HeldOutEvaluationManifest,
    replicates_per_case: int,
    run_trial: PairedTrialExecutor,
    protocol: MeasurementProtocol | None = None,
    confidence_level: float = 0.95,
) -> PairedRedAblationExecution:
    """Execute a matched-pair ablation and retain its persistence-grade observations."""

    selected = select_manifest_cases(cases, manifest=manifest, evaluation=True)
    cases_by_id = {case.id: case for case in selected}
    plan = build_counterbalanced_pair_plan(
        contract=contract,
        manifest=manifest,
        replicates_per_case=replicates_per_case,
    )

    observations: list[PairedRedObservation] = []
    for pair in plan:
        second_arm = (
            AblationArm.TREATMENT
            if pair.first_arm == AblationArm.BASELINE
            else AblationArm.BASELINE
        )
        for arm in (pair.first_arm, second_arm):
            observation = await run_trial(
                arm,
                cases_by_id[pair.case_id],
                pair.replicate,
                pair.pair_seed,
            )
            _validate_executor_observation(
                observation,
                contract=contract,
                expected_arm=arm,
                expected_case_id=pair.case_id,
                expected_replicate=pair.replicate,
                expected_pair_seed=pair.pair_seed,
            )
            observations.append(observation)

    frozen_observations = tuple(observations)
    report = summarize_paired_red_ablation(
        frozen_observations,
        contract=contract,
        manifest=manifest,
        protocol=protocol,
        confidence_level=confidence_level,
    )
    return PairedRedAblationExecution(
        plan=plan,
        observations=frozen_observations,
        report=report,
    )


async def execute_paired_red_ablation(
    *,
    cases: Iterable[AttackCase],
    contract: PairedRedAblationContract,
    manifest: HeldOutEvaluationManifest,
    replicates_per_case: int,
    run_trial: PairedTrialExecutor,
    protocol: MeasurementProtocol | None = None,
    confidence_level: float = 0.95,
) -> PairedRedAblationReport:
    """Backward-compatible report-only wrapper around the persistence-grade runner."""

    execution = await execute_paired_red_ablation_with_observations(
        cases=cases,
        contract=contract,
        manifest=manifest,
        replicates_per_case=replicates_per_case,
        run_trial=run_trial,
        protocol=protocol,
        confidence_level=confidence_level,
    )
    return execution.report


def _validate_executor_observation(
    observation: PairedRedObservation,
    *,
    contract: PairedRedAblationContract,
    expected_arm: AblationArm,
    expected_case_id: str,
    expected_replicate: int,
    expected_pair_seed: int | None,
) -> None:
    if observation.arm != expected_arm:
        raise ValueError("paired trial executor returned the wrong ablation arm")
    if observation.case_id != expected_case_id:
        raise ValueError("paired trial executor returned the wrong case_id")
    if observation.replicate != expected_replicate:
        raise ValueError("paired trial executor returned the wrong replicate")

    expected_policy = (
        contract.baseline_policy_fingerprint
        if expected_arm == AblationArm.BASELINE
        else contract.treatment_policy_fingerprint
    )
    if observation.policy_fingerprint != expected_policy:
        raise ValueError("paired trial executor returned the wrong policy fingerprint")

    if (
        contract.pairing_mode == PairingMode.CASE_REPLICATE_SEED
        and observation.pair_seed != expected_pair_seed
    ):
        raise ValueError("paired trial executor did not preserve the scheduled pair seed")
