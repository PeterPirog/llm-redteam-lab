import asyncio
from pathlib import Path

from llm_redteam.campaigns import CampaignEngine
from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import CompromiseOutcome
from llm_redteam.judges import DeterministicJudge
from llm_redteam.metrics import summarize_campaign
from llm_redteam.targets import HardenedVaultTarget, VulnerableVaultTarget

ROOT = Path(__file__).resolve().parents[1]
TEXT_CORPUS = ROOT / "corpus" / "native" / "smoke" / "writing-reasoning.yaml"
CANARY = "RT_CANARY_PINEAPPLE_739"


def test_vulnerable_target_is_detected_without_llm_inference() -> None:
    cases = tuple(load_corpus_file(TEXT_CORPUS).cases)
    engine = CampaignEngine(
        target=VulnerableVaultTarget(canary=CANARY),
        judge=DeterministicJudge(canary=CANARY),
    )

    results = asyncio.run(engine.run(cases))
    metrics = summarize_campaign(results)

    assert len(results) == 5
    assert results[0].outcome == CompromiseOutcome.PASS
    assert all(
        result.outcome == CompromiseOutcome.MODEL_COMPROMISE
        for result in results[1:]
    )
    assert metrics.attack_success_rate.successes == 4
    assert metrics.attack_success_rate.trials == 5
    assert metrics.model_compromise_rate.value == 0.8
    assert metrics.system_compromise_rate.value == 0.0


def test_hardened_target_blocks_native_canary_attacks() -> None:
    cases = tuple(load_corpus_file(TEXT_CORPUS).cases)
    engine = CampaignEngine(
        target=HardenedVaultTarget(canary=CANARY),
        judge=DeterministicJudge(canary=CANARY),
    )

    results = asyncio.run(engine.run(cases))
    metrics = summarize_campaign(results)

    assert all(result.outcome == CompromiseOutcome.PASS for result in results)
    assert metrics.attack_success_rate.value == 0.0
    assert metrics.model_compromise_rate.value == 0.0
    assert metrics.system_compromise_rate.value == 0.0
    assert metrics.attack_success_rate.ci_high is not None
    assert metrics.attack_success_rate.ci_high > 0.0
