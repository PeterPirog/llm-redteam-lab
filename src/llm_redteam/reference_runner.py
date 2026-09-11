"""Executable paired runner for the staged local multi-turn Red reference experiment.

The runner is intentionally provider-independent. It executes the frozen held-out reference
set under counterbalanced baseline/treatment Red policies, records exact per-trial resource
usage from the shared arm budget ledgers, persists both campaigns and their measurement
provenance, and then persists the paired ablation experiment.

No local model name or endpoint is hard-coded here. Operator-facing wiring belongs in the CLI
and runtime configuration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from uuid import uuid4

from .budget import BudgetLedger
from .campaigns.lifecycle import METRIC_DEFINITION_VERSION
from .campaigns.multiturn import ConversationRunResult, MultiTurnCampaignEngine
from .domain import AttackCase
from .evaluation_protocol import held_out_evaluation_protocol
from .evaluation_sets import (
    HeldOutEvaluationManifest,
    fingerprint_attack_case,
    select_manifest_cases,
)
from .judges.base import Judge
from .judges.deterministic import DeterministicJudge
from .model_client import RoleModelClient
from .model_roles import ModelsConfig
from .red.ablation import (
    AblationArm,
    PairedRedAblationContract,
    PairedRedAblationReport,
    PairedRedObservation,
    PairingMode,
    build_counterbalanced_pair_plan,
    observation_from_run,
    summarize_paired_red_ablation,
)
from .red.qualification import RedPolicyQualificationDecision, qualify_red_policy
from .red.runtime import RedStrategyRuntime, build_model_backed_red_policy_descriptor
from .reference_evaluation import (
    ReferenceEvaluationPreflight,
    ReferenceEvaluationSpec,
    ReferenceEvaluationStage,
    build_reference_evaluation_manifest,
    preflight_reference_evaluation,
)
from .runtime_config import BudgetConfigDocument
from .storage.ablation_repository import (
    build_red_ablation_experiment_snapshot,
    save_red_ablation_experiment,
    save_red_ablation_observations,
)
from .storage.campaign_status import CampaignTerminalStatus, finish_campaign
from .storage.evaluation_set_repository import save_evaluation_set_manifest
from .storage.measurement_repository import (
    build_evaluation_campaign_measurement_snapshot,
    fingerprint_attack_policy,
    fingerprint_budget,
    fingerprint_corpus_snapshot,
    fingerprint_judge_policy,
    save_campaign_measurement_snapshot,
)
from .storage.repository import ExperimentRepository
from .targets.base import TargetAdapter


@dataclass(frozen=True, slots=True)
class ReferenceArmResult:
    arm: AblationArm
    campaign_id: str
    measurement_hash: str
    observations: tuple[PairedRedObservation, ...]


@dataclass(frozen=True, slots=True)
class ReferenceEvaluationRunResult:
    """Auditable output of one smoke or qualification reference stage."""

    stage: ReferenceEvaluationStage
    preflight: ReferenceEvaluationPreflight
    manifest: HeldOutEvaluationManifest
    baseline: ReferenceArmResult
    treatment: ReferenceArmResult
    report: PairedRedAblationReport
    qualification: RedPolicyQualificationDecision | None


@dataclass(slots=True)
class _ArmRuntime:
    arm: AblationArm
    policy_fingerprint: str
    campaign_id: str
    measurement_hash: str
    ledger: BudgetLedger
    red_runtime: RedStrategyRuntime
    observations: list[PairedRedObservation]


def reference_corpus_snapshot_hash(cases: tuple[AttackCase, ...]) -> str:
    """Bind the reference manifest to exact normalized case content, order-independently."""

    if not cases:
        raise ValueError("reference corpus cannot be empty")
    return fingerprint_corpus_snapshot(
        {
            case.id: fingerprint_attack_case(case)
            for case in sorted(cases, key=lambda item: item.id)
        }
    )


async def run_reference_evaluation_stage(
    *,
    stage: ReferenceEvaluationStage,
    spec: ReferenceEvaluationSpec,
    cases: tuple[AttackCase, ...],
    budgets: BudgetConfigDocument,
    models: ModelsConfig,
    target: TargetAdapter,
    judge: Judge,
    judge_policy_descriptor: object,
    red_model_client: RoleModelClient,
    repository: ExperimentRepository,
    run_id: str | None = None,
) -> ReferenceEvaluationRunResult:
    """Execute one frozen reference stage and persist its paired evidence.

    The two Red arms are separate persisted campaigns, but their trials are executed in the
    deterministic counterbalanced pair order declared by ``PairedRedAblationContract``. This
    avoids turning wall-clock order into an uncontrolled treatment while preserving separate
    arm-wide budgets.
    """

    preflight = preflight_reference_evaluation(
        spec=spec,
        cases=cases,
        budgets=budgets,
        target=target.identity,
    )
    if not preflight.ready:
        raise ValueError("reference evaluation preflight failed: " + "; ".join(preflight.issues))
    if spec.require_deterministic_canary_judge and not isinstance(judge, DeterministicJudge):
        raise ValueError("reference evaluation v1 requires DeterministicJudge")
    if spec.qualification_policy.require_seed_pairing:
        raise ValueError("reference evaluation v1 does not yet provide stochastic seed pairing")

    manifest = build_reference_evaluation_manifest(
        spec=spec,
        cases=cases,
        corpus_snapshot_hash=reference_corpus_snapshot_hash(cases),
    )
    selected = select_manifest_cases(cases, manifest=manifest, evaluation=True)
    selected_by_id = {case.id: case for case in selected}
    stage_plan = preflight.smoke if stage == ReferenceEvaluationStage.INSTRUMENTATION_SMOKE else preflight.qualification
    profile_name, effective_budget = budgets.profile(stage_plan.budget_profile)

    repository.create_schema()
    target_snapshot_id = repository.save_target(target.identity)
    save_evaluation_set_manifest(repository.engine, manifest)

    judge_fingerprint = fingerprint_judge_policy(judge_policy_descriptor)
    budget_fingerprint = fingerprint_budget(effective_budget.model_dump(mode="json"))
    baseline_descriptor = build_model_backed_red_policy_descriptor(
        policy=spec.baseline_policy,
        purpose=held_out_evaluation_protocol().purpose,
        target_class=spec.target_class,
        target_mode=spec.target_mode,
        session_mode=spec.session_mode,
        campaign_budget=effective_budget,
        models=models,
    )
    treatment_descriptor = build_model_backed_red_policy_descriptor(
        policy=spec.treatment_policy,
        purpose=held_out_evaluation_protocol().purpose,
        target_class=spec.target_class,
        target_mode=spec.target_mode,
        session_mode=spec.session_mode,
        campaign_budget=effective_budget,
        models=models,
    )
    baseline_fingerprint = fingerprint_attack_policy(baseline_descriptor)
    treatment_fingerprint = fingerprint_attack_policy(treatment_descriptor)

    resolved_run_id = run_id or uuid4().hex
    experiment_id = f"{spec.experiment_id}:{stage.value.lower()}:{resolved_run_id}"
    baseline_campaign_id = f"{experiment_id}:baseline"
    treatment_campaign_id = f"{experiment_id}:treatment"

    contract = PairedRedAblationContract(
        experiment_id=experiment_id,
        target_snapshot_id=target_snapshot_id,
        judge_fingerprint=judge_fingerprint,
        budget_fingerprint=budget_fingerprint,
        evaluation_manifest_hash=manifest.content_hash,
        metric_definition_version=METRIC_DEFINITION_VERSION,
        session_mode=spec.session_mode.value,
        changed_component="red_search_policy",
        baseline_policy_fingerprint=baseline_fingerprint,
        treatment_policy_fingerprint=treatment_fingerprint,
        pairing_mode=PairingMode.CASE_REPLICATE,
    )

    baseline = _start_arm(
        arm=AblationArm.BASELINE,
        campaign_id=baseline_campaign_id,
        policy=spec.baseline_policy,
        policy_fingerprint=baseline_fingerprint,
        repository=repository,
        target=target,
        judge_fingerprint=judge_fingerprint,
        budget_fingerprint=budget_fingerprint,
        budget_profile=profile_name,
        effective_budget=effective_budget,
        models=models,
        red_model_client=red_model_client,
        manifest=manifest,
        spec=spec,
        stage=stage,
    )
    treatment = _start_arm(
        arm=AblationArm.TREATMENT,
        campaign_id=treatment_campaign_id,
        policy=spec.treatment_policy,
        policy_fingerprint=treatment_fingerprint,
        repository=repository,
        target=target,
        judge_fingerprint=judge_fingerprint,
        budget_fingerprint=budget_fingerprint,
        budget_profile=profile_name,
        effective_budget=effective_budget,
        models=models,
        red_model_client=red_model_client,
        manifest=manifest,
        spec=spec,
        stage=stage,
    )
    arms = {AblationArm.BASELINE: baseline, AblationArm.TREATMENT: treatment}

    try:
        for pair in build_counterbalanced_pair_plan(
            contract=contract,
            manifest=manifest,
            replicates_per_case=stage_plan.replicates_per_case,
        ):
            second = (
                AblationArm.TREATMENT
                if pair.first_arm == AblationArm.BASELINE
                else AblationArm.BASELINE
            )
            for arm in (pair.first_arm, second):
                context = arms[arm]
                case = selected_by_id[pair.case_id]
                observation = await _run_trial(
                    context=context,
                    case=case,
                    replicate=pair.replicate,
                    pair_seed=pair.pair_seed,
                    target=target,
                    judge=judge,
                    repository=repository,
                    target_snapshot_id=target_snapshot_id,
                    session_mode=spec.session_mode,
                )
                context.observations.append(observation)

        observations = tuple((*baseline.observations, *treatment.observations))
        report = summarize_paired_red_ablation(
            observations,
            contract=contract,
            manifest=manifest,
        )
    except Exception:
        finish_campaign(repository.engine, campaign_id=baseline.campaign_id, status=CampaignTerminalStatus.FAILED)
        finish_campaign(repository.engine, campaign_id=treatment.campaign_id, status=CampaignTerminalStatus.FAILED)
        raise

    finish_campaign(repository.engine, campaign_id=baseline.campaign_id, status=CampaignTerminalStatus.COMPLETED)
    finish_campaign(repository.engine, campaign_id=treatment.campaign_id, status=CampaignTerminalStatus.COMPLETED)

    experiment = build_red_ablation_experiment_snapshot(
        contract=contract,
        baseline_campaign_id=baseline.campaign_id,
        treatment_campaign_id=treatment.campaign_id,
        baseline_measurement_hash=baseline.measurement_hash,
        treatment_measurement_hash=treatment.measurement_hash,
    )
    save_red_ablation_experiment(repository.engine, experiment)
    save_red_ablation_observations(
        repository.engine,
        experiment_id=contract.experiment_id,
        observations=observations,
    )

    qualification = None
    if stage == ReferenceEvaluationStage.POLICY_QUALIFICATION:
        qualification = qualify_red_policy(report, policy=spec.qualification_policy)

    return ReferenceEvaluationRunResult(
        stage=stage,
        preflight=preflight,
        manifest=manifest,
        baseline=_freeze_arm(baseline),
        treatment=_freeze_arm(treatment),
        report=report,
        qualification=qualification,
    )


def _start_arm(
    *,
    arm: AblationArm,
    campaign_id: str,
    policy,
    policy_fingerprint: str,
    repository: ExperimentRepository,
    target: TargetAdapter,
    judge_fingerprint: str,
    budget_fingerprint: str,
    budget_profile: str,
    effective_budget,
    models: ModelsConfig,
    red_model_client: RoleModelClient,
    manifest: HeldOutEvaluationManifest,
    spec: ReferenceEvaluationSpec,
    stage: ReferenceEvaluationStage,
) -> _ArmRuntime:
    ledger = BudgetLedger(effective_budget)
    red_runtime = RedStrategyRuntime(
        policy=policy,
        purpose=held_out_evaluation_protocol().purpose,
        target_class=spec.target_class,
        target_mode=spec.target_mode,
        session_mode=spec.session_mode,
        campaign_budget=effective_budget,
        models=models,
        model_client=red_model_client,
        budget=ledger,
    )
    configuration_hash = _canonical_hash(
        {
            "reference_experiment": spec.experiment_id,
            "stage": stage.value,
            "arm": arm.value,
            "target_snapshot_id": repository.target_snapshot_id(target.identity),
            "budget_profile": budget_profile,
            "budget_fingerprint": budget_fingerprint,
            "attack_policy_fingerprint": policy_fingerprint,
            "judge_policy_fingerprint": judge_fingerprint,
            "evaluation_manifest_hash": manifest.content_hash,
            "metric_definition_version": METRIC_DEFINITION_VERSION,
        }
    )
    target_snapshot_id = repository.target_snapshot_id(target.identity)
    repository.start_campaign(
        campaign_id=campaign_id,
        target_snapshot_id=target_snapshot_id,
        configuration_hash=configuration_hash,
        metric_definition_version=METRIC_DEFINITION_VERSION,
    )
    measurement = build_evaluation_campaign_measurement_snapshot(
        campaign_id=campaign_id,
        target_snapshot_id=target_snapshot_id,
        campaign_configuration_hash=configuration_hash,
        metric_definition_version=METRIC_DEFINITION_VERSION,
        protocol=held_out_evaluation_protocol(),
        attack_policy_fingerprint=policy_fingerprint,
        manifest=manifest,
        judge_policy_fingerprint=judge_fingerprint,
        budget_fingerprint=budget_fingerprint,
    )
    measurement_hash = save_campaign_measurement_snapshot(repository.engine, measurement)
    return _ArmRuntime(
        arm=arm,
        policy_fingerprint=policy_fingerprint,
        campaign_id=campaign_id,
        measurement_hash=measurement_hash,
        ledger=ledger,
        red_runtime=red_runtime,
        observations=[],
    )


async def _run_trial(
    *,
    context: _ArmRuntime,
    case: AttackCase,
    replicate: int,
    pair_seed: int | None,
    target: TargetAdapter,
    judge: Judge,
    repository: ExperimentRepository,
    target_snapshot_id: str,
    session_mode,
) -> PairedRedObservation:
    before = context.ledger.snapshot()
    strategy = context.red_runtime.strategy_for(case)
    conversation_id = (
        f"{context.campaign_id}:conv:{case.id}:{replicate}"
    )
    engine = MultiTurnCampaignEngine(
        target=target,
        judge=judge,
        conversation_budget=context.red_runtime.conversation_budget,
        budget=context.ledger,
    )
    result: ConversationRunResult = await engine.run_case(
        case,
        strategy,
        session_mode=session_mode,
        conversation_id=conversation_id,
    )
    after = context.ledger.snapshot()

    attack_instance_id = f"{context.campaign_id}:attack:{case.id}:{replicate}"
    repository.record_attack(
        attack_instance_id=attack_instance_id,
        campaign_id=context.campaign_id,
        case_id=case.id,
        attack_family=case.attack_family[0],
        interaction_mode=case.interaction_mode,
        payload_hash=fingerprint_attack_case(case),
    )
    repository.save_conversation(
        result,
        attack_instance_id=attack_instance_id,
        target_snapshot_id=target_snapshot_id,
    )
    context.red_runtime.observe(case=case, strategy=strategy, result=result)
    return observation_from_run(
        arm=context.arm,
        replicate=replicate,
        policy_fingerprint=context.policy_fingerprint,
        result=result,
        budget_before=before,
        budget_after=after,
        pair_seed=pair_seed,
    )


def _freeze_arm(context: _ArmRuntime) -> ReferenceArmResult:
    return ReferenceArmResult(
        arm=context.arm,
        campaign_id=context.campaign_id,
        measurement_hash=context.measurement_hash,
        observations=tuple(context.observations),
    )


def _canonical_hash(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(raw.encode()).hexdigest()
