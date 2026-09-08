from llm_redteam.domain import AttackTier, TargetClass, TargetMode
from llm_redteam.red import AttackObservation, HeuristicRedPlanner


def _observation(
    attack_id: str,
    family: str,
    *,
    success: bool | None,
    generation: int = 0,
    novelty: float = 1.0,
    refused: bool = False,
) -> AttackObservation:
    return AttackObservation(
        attack_id=attack_id,
        hypothesis_id=f"H-{attack_id}",
        attack_family=family,
        generation=generation,
        objective_violated=success,
        model_compromise=success is True,
        system_compromise=False,
        refused=refused,
        novelty_score=novelty,
    )


def test_planner_starts_with_cheapest_untried_family() -> None:
    planner = HeuristicRedPlanner(max_tier=AttackTier.T4)
    plan = planner.next_plan(
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        security_objective_id="INV-001",
        history=(),
    )

    assert plan is not None
    assert plan.hypothesis.complexity_tier == AttackTier.T1
    assert plan.strategy == "static_corpus"
    assert plan.parent_attack_id is None


def test_planner_explores_distinct_families_before_repeating() -> None:
    planner = HeuristicRedPlanner(max_tier=AttackTier.T2)
    first = planner.next_plan(
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        security_objective_id="INV-001",
        history=(),
    )
    assert first is not None

    history = (
        _observation("A-1", first.hypothesis.attack_family, success=False),
    )
    second = planner.next_plan(
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        security_objective_id="INV-001",
        history=history,
    )

    assert second is not None
    assert second.hypothesis.attack_family != first.hypothesis.attack_family


def test_planner_uses_successful_attack_as_genealogy_parent_after_coverage() -> None:
    planner = HeuristicRedPlanner(max_tier=AttackTier.T1)
    history = (
        _observation("A-1", "direct_instruction_override", success=True, novelty=0.9),
        _observation("A-2", "persona_roleplay", success=False, refused=True),
    )

    plan = planner.next_plan(
        target_class=TargetClass.WRITING,
        target_mode=TargetMode.MODEL,
        security_objective_id="INV-001",
        history=history,
    )

    assert plan is not None
    assert plan.hypothesis.attack_family == "direct_instruction_override"
    assert plan.parent_attack_id == "A-1"
    assert plan.generation == 1
    assert plan.strategy == "mutate_and_retest"


def test_coding_planner_never_falls_back_to_text_persona_families() -> None:
    planner = HeuristicRedPlanner()
    plan = planner.next_plan(
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        security_objective_id="INV-REPO",
        history=(),
    )

    assert plan is not None
    assert plan.hypothesis.attack_family == "repository_prompt_injection"
    assert plan.hypothesis.complexity_tier == AttackTier.T4
