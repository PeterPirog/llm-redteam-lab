from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.red.attacker_pool import (
    AttackerPoolContract,
    AttackerVariant,
    build_attacker_pool_trial_schedule,
)


def _contract() -> AttackerPoolContract:
    return AttackerPoolContract(
        experiment_id="schedule-test",
        purpose=CampaignPurpose.DISCOVERY,
        target_snapshot_id="target-1",
        scope_manifest_hash="a" * 64,
        budget_fingerprint="b" * 64,
        case_ids=("case-b", "case-a"),
        replicates_per_case=2,
        variants=(
            AttackerVariant(
                id="attacker-a",
                planner_fingerprint="1" * 64,
                mutator_fingerprint="2" * 64,
            ),
            AttackerVariant(
                id="attacker-b",
                planner_fingerprint="3" * 64,
                mutator_fingerprint="4" * 64,
            ),
            AttackerVariant(
                id="attacker-c",
                planner_fingerprint="5" * 64,
                mutator_fingerprint="6" * 64,
            ),
        ),
    )


def test_schedule_is_complete_deterministic_and_counterbalanced() -> None:
    contract = _contract()
    first = build_attacker_pool_trial_schedule(contract)
    second = build_attacker_pool_trial_schedule(contract)

    assert first == second
    assert len(first) == len(contract.expected_opportunities) * len(contract.variants)
    assert [assignment.order_index for assignment in first] == list(range(len(first)))

    starts: list[str] = []
    for opportunity_index, opportunity in enumerate(contract.expected_opportunities):
        rows = [
            assignment
            for assignment in first
            if assignment.opportunity_index == opportunity_index
        ]
        assert {row.variant_id for row in rows} == {
            variant.id for variant in contract.variants
        }
        assert {row.opportunity_key for row in rows} == {opportunity}
        starts.append(rows[0].variant_id)

    assert starts[:3] == ["attacker-a", "attacker-b", "attacker-c"]


def test_schedule_order_is_bound_to_contract_variant_order() -> None:
    contract = _contract()
    reversed_contract = contract.model_copy(
        update={"variants": tuple(reversed(contract.variants))}
    )

    assert contract.contract_fingerprint != reversed_contract.contract_fingerprint
    assert (
        build_attacker_pool_trial_schedule(contract)[0].variant_id
        != build_attacker_pool_trial_schedule(reversed_contract)[0].variant_id
    )
