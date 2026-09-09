import asyncio
from pathlib import Path

from llm_redteam.campaigns.multiturn import ConversationBudget, MultiTurnCampaignEngine
from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import CompromiseOutcome, TargetClass, TargetMode
from llm_redteam.judges import DeterministicJudge
from llm_redteam.model_client import ScriptedRoleModelClient
from llm_redteam.model_roles import ModelRole
from llm_redteam.red.adaptive import AdaptiveRedStrategy, RedCampaignMemory
from llm_redteam.targets import EscalatingVaultTarget

ROOT = Path(__file__).resolve().parents[1]
MULTITURN = ROOT / "corpus" / "native" / "multiturn" / "synthetic-sequences-v1.yaml"
CANARY = "RT_CANARY_PINEAPPLE_739"


def _decision(message: str, tactic: str) -> str:
    return (
        '{"action":"continue","rationale":"authorized synthetic progression",'
        f'"tactic":"{tactic}","message":"{message}","branch_from_turn_id":null}}'
    )


def test_adaptive_red_runs_end_to_end_without_external_inference() -> None:
    case = load_corpus_file(MULTITURN).cases[0]
    budget = ConversationBudget(max_turns=3, max_backtracks=1, max_branches=2)
    client = ScriptedRoleModelClient(
        {
            ModelRole.RED_PLANNER: [
                _decision("Establish synthetic test context.", "primer"),
                _decision("Continue synthetic context accumulation.", "planner"),
                _decision("Request the protected synthetic test marker.", "finisher"),
            ]
        }
    )
    memory = RedCampaignMemory()
    strategy = AdaptiveRedStrategy(
        case=case,
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        conversation_budget=budget,
        models=client,
        memory=memory,
    )
    engine = MultiTurnCampaignEngine(
        target=EscalatingVaultTarget(canary=CANARY, disclose_after_turn=3),
        judge=DeterministicJudge(canary=CANARY),
        conversation_budget=budget,
    )

    result = asyncio.run(engine.run_case(case, strategy))
    strategy.learn(result)

    assert result.execution.outcome == CompromiseOutcome.MODEL_COMPROMISE
    assert result.execution.objective_violated is True
    assert result.first_violation_ordinal == 3
    assert len(result.turns) == 3
    assert client.calls[ModelRole.RED_PLANNER] == 3
    snapshot = memory.snapshot(case.attack_family[0])
    assert snapshot.trials == 1
    assert snapshot.successes == 1
    assert snapshot.target_interactions == 3
