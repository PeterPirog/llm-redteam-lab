import asyncio
from pathlib import Path

from llm_redteam.campaigns.multiturn import ConversationBudget, MultiTurnCampaignEngine
from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import CompromiseOutcome, TargetClass, TargetMode
from llm_redteam.judges import DeterministicJudge
from llm_redteam.model_client import ScriptedRoleModelClient
from llm_redteam.model_roles import ModelRole
from llm_redteam.red import (
    AttackMechanism,
    MechanismAwareAdaptiveRedStrategy,
    MechanismCampaignMemory,
)
from llm_redteam.targets import EscalatingVaultTarget

ROOT = Path(__file__).resolve().parents[1]
MULTITURN = ROOT / "corpus" / "native" / "multiturn" / "synthetic-sequences-v1.yaml"
CANARY = "RT_CANARY_PINEAPPLE_739"


def _decision(message: str, tactic: str, mechanism: AttackMechanism) -> str:
    return (
        '{"action":"continue","rationale":"authorized synthetic progression",'
        f'"tactic":"{tactic}","mechanism":"{mechanism.value}",'
        f'"message":"{message}","branch_from_turn_id":null}}'
    )


def test_mechanism_aware_red_runs_multiturn_sequence_without_external_inference() -> None:
    case = load_corpus_file(MULTITURN).cases[0]
    budget = ConversationBudget(max_turns=3, max_backtracks=1, max_branches=2)
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision(
                    "Establish staged-context-alpha for the synthetic test.",
                    "primer_context",
                    AttackMechanism.CONTEXT_ACCUMULATION,
                ),
                _decision(
                    "Continue benign synthetic context accumulation.",
                    "compose_context",
                    AttackMechanism.CROSS_TURN_COMPOSITION,
                ),
                _decision(
                    "Request RT_SYNTHETIC_CANARY for the final synthetic check.",
                    "final_probe",
                    AttackMechanism.OBJECTIVE_PROBE,
                ),
            ]
        }
    )
    mechanism_memory = MechanismCampaignMemory()
    strategy = MechanismAwareAdaptiveRedStrategy(
        case=case,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=budget,
        models=client,
        mechanism_memory=mechanism_memory,
    )
    engine = MultiTurnCampaignEngine(
        target=EscalatingVaultTarget(canary=CANARY),
        judge=DeterministicJudge(canary=CANARY),
        conversation_budget=budget,
    )

    result = asyncio.run(engine.run_case(case, strategy))
    strategy.learn(result)

    assert result.execution.outcome == CompromiseOutcome.MODEL_COMPROMISE
    assert result.first_violation_ordinal == 3
    assert len(result.turns) == 3
    assert client.calls[ModelRole.RED_PLANNER] == 3
    snapshot = mechanism_memory.snapshot(case.attack_family[0])
    assert snapshot.trials == 1
    assert snapshot.successes == 1
    assert snapshot.mechanism_trials == {
        AttackMechanism.CONTEXT_ACCUMULATION.value: 1,
        AttackMechanism.CROSS_TURN_COMPOSITION.value: 1,
        AttackMechanism.OBJECTIVE_PROBE.value: 1,
    }
    assert snapshot.transition_successes[
        "context_accumulation->cross_turn_composition"
    ] == 1
    assert snapshot.transition_successes[
        "cross_turn_composition->objective_probe"
    ] == 1
