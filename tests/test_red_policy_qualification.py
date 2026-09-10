from __future__ import annotations

from typing import Any, cast

from llm_redteam.metrics import wilson_rate
from llm_redteam.red.ablation import (
    PairedRedAblationContract,
    PairedRedAblationReport,
    PairingMode,
)
from llm_redteam.red.qualification import (
    RedPolicyQualificationPolicy,
    RedPolicyQualificationStatus,
    qualify_red_policy,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64


def _report(
    *,
    pair_count: int = 40,
    baseline_only: int = 1,
    treatment_only: int = 10,
    delta: float = 0.225,
    p_value: float = 0.0117,
    pairing_mode: PairingMode = PairingMode.CASE_REPLICATE,
    interaction_delta: float = 0.5,
    output_token_delta: float = 20.0,
) -> PairedRedAblationReport:
    discordant = baseline_only + treatment_only
    return PairedRedAblationReport(
        contract=PairedRedAblationContract(
            experiment_id="qualification-test",
            target_snapshot_id="target-snapshot",
            judge_fingerprint=HASH_A,
            budget_fingerprint=HASH_B,
            evaluation_manifest_hash=HASH_C,
            metric_definition_version="v2",
            session_mode="REPLAY",
            changed_component="mechanism_scheduler",
            baseline_policy_fingerprint=HASH_D,
            treatment_policy_fingerprint=HASH_E,
            pairing_mode=pairing_mode,
        ),
        pair_count=pair_count,
        baseline=cast(Any, None),
        treatment=cast(Any, None),
        objective_violation_rate_delta=delta,
        model_compromise_rate_delta=delta,
        system_compromise_rate_delta=0.0,
        both_objective_successes=5,
        baseline_only_objective_successes=baseline_only,
        treatment_only_objective_successes=treatment_only,
        neither_objective_successes=max(0, pair_count - 5 - discordant),
        discordant_pairs=discordant,
        exact_mcnemar_p_value=p_value,
        treatment_win_rate_among_discordant=wilson_rate(treatment_only, discordant),
        mean_target_interaction_delta=interaction_delta,
        median_target_interaction_delta=interaction_delta,
        mean_planner_call_delta=0.0,
        mean_mutator_call_delta=0.0,
        mean_output_token_delta=output_token_delta,
        median_first_violation_ordinal_delta_on_joint_success=-1.0,
    )


def test_statistically_better_treatment_is_qualified() -> None:
    decision = qualify_red_policy(_report())

    assert decision.status == RedPolicyQualificationStatus.QUALIFIED
    assert decision.reasons == ()
    assert decision.treatment_only_successes == 10
    assert decision.baseline_only_successes == 1


def test_small_or_non_significant_experiment_remains_inconclusive() -> None:
    decision = qualify_red_policy(
        _report(pair_count=8, baseline_only=0, treatment_only=3, delta=0.375, p_value=0.25)
    )

    assert decision.status == RedPolicyQualificationStatus.INCONCLUSIVE
    assert any("min_pair_count" in reason for reason in decision.reasons)
    assert any("McNemar" in reason for reason in decision.reasons)


def test_no_discordant_pairs_do_not_prove_superiority() -> None:
    decision = qualify_red_policy(
        _report(
            pair_count=40,
            baseline_only=0,
            treatment_only=0,
            delta=0.0,
            p_value=1.0,
        )
    )

    assert decision.status == RedPolicyQualificationStatus.INCONCLUSIVE
    assert any("no discordant pairs" in reason for reason in decision.reasons)


def test_significantly_worse_treatment_is_rejected() -> None:
    decision = qualify_red_policy(
        _report(
            baseline_only=10,
            treatment_only=1,
            delta=-0.225,
            p_value=0.0117,
        )
    )

    assert decision.status == RedPolicyQualificationStatus.REJECTED
    assert any("treatment is worse" in reason for reason in decision.reasons)


def test_operational_cost_ceiling_is_a_separate_rejection_gate() -> None:
    decision = qualify_red_policy(
        _report(interaction_delta=1.5, output_token_delta=250.0),
        policy=RedPolicyQualificationPolicy(
            max_mean_target_interaction_delta=1.0,
            max_mean_output_token_delta=200.0,
        ),
    )

    assert decision.status == RedPolicyQualificationStatus.REJECTED
    assert any("target-interaction" in reason for reason in decision.reasons)
    assert any("output-token" in reason for reason in decision.reasons)


def test_seed_pairing_requirement_fails_inconclusive_not_rejected() -> None:
    decision = qualify_red_policy(
        _report(pairing_mode=PairingMode.CASE_REPLICATE),
        policy=RedPolicyQualificationPolicy(require_seed_pairing=True),
    )

    assert decision.status == RedPolicyQualificationStatus.INCONCLUSIVE
    assert any("CASE_REPLICATE_SEED" in reason for reason in decision.reasons)


def test_seed_paired_superiority_can_qualify() -> None:
    decision = qualify_red_policy(
        _report(pairing_mode=PairingMode.CASE_REPLICATE_SEED),
        policy=RedPolicyQualificationPolicy(require_seed_pairing=True),
    )

    assert decision.status == RedPolicyQualificationStatus.QUALIFIED
