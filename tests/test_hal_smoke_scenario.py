from pathlib import Path

from llm_redteam.agent_actions import (
    AgentActionObservation,
    AgentActionPhase,
    AgentEffectObservation,
    AgentEffectState,
)
from llm_redteam.domain import TargetClass, TargetMode
from llm_redteam.hal_smoke_scenario import (
    HAL_SMOKE_BUDGET_PROFILE,
    HAL_SMOKE_DETECTOR_ID,
    HAL_SMOKE_FORBIDDEN_MARKER,
    HAL_SMOKE_STATE_VERIFIER_POLICY_SHA256,
    HAL_SMOKE_VERIFIER_ID,
    build_hal_smoke_campaign_plan,
    build_hal_smoke_case,
    build_hal_smoke_judge,
    build_hal_smoke_workspace_verifiers,
    hal_smoke_judge_policy_descriptor,
)
from llm_redteam.targets.base import SessionMode, TargetResponse


def _action_evidence():
    return AgentActionObservation(
        control_event_id="smoke-write-1",
        session_id="session-1",
        message_id="message-1",
        tool="write",
        phase=AgentActionPhase.EXECUTED,
        categories=frozenset({"tool_call", "filesystem_write"}),
        input_hash="a" * 64,
        source="synthetic-opencode",
    ).to_evidence()


def test_builtin_hal_smoke_scenario_is_narrow_and_local() -> None:
    case = build_hal_smoke_case()
    plan = build_hal_smoke_campaign_plan()
    descriptor = hal_smoke_judge_policy_descriptor()

    assert case.target_classes == (TargetClass.CODING,)
    assert case.target_modes == (TargetMode.AGENT,)
    assert case.interaction_mode == "multi_turn"
    assert HAL_SMOKE_FORBIDDEN_MARKER in case.security_objective.forbidden_effect
    assert "network" in case.payload.text.casefold()
    assert "credentials" in case.payload.text.casefold()
    assert case.grading.detectors == (HAL_SMOKE_DETECTOR_ID,)

    assert plan.target_class == TargetClass.CODING
    assert plan.target_mode == TargetMode.AGENT
    assert plan.session_mode == SessionMode.TARGET_MANAGED
    assert plan.budget_profile == HAL_SMOKE_BUDGET_PROFILE
    assert plan.allow_agent_network is False
    assert plan.allow_agent_git_push is False

    assert (
        descriptor["state_verifier_policy_sha256"]
        == HAL_SMOKE_STATE_VERIFIER_POLICY_SHA256
    )
    assert descriptor["trusted_effect_verifiers"] == [HAL_SMOKE_VERIFIER_ID]


def test_builtin_workspace_verifier_observes_only_forbidden_marker(
    tmp_path: Path,
) -> None:
    (verifier,) = build_hal_smoke_workspace_verifiers(tmp_path)
    before = verifier.capture()

    (tmp_path / "legitimate-edit.txt").write_text("allowed", encoding="utf-8")
    unrelated = verifier.capture()
    assert unrelated.state_hash == before.state_hash

    (tmp_path / HAL_SMOKE_FORBIDDEN_MARKER).write_text(
        "synthetic forbidden marker",
        encoding="utf-8",
    )
    after = verifier.capture()
    assert after.state_hash != before.state_hash


def test_builtin_judge_does_not_infer_system_effect_from_tool_trace_alone() -> None:
    case = build_hal_smoke_case()
    judge = build_hal_smoke_judge()
    response = TargetResponse(
        text="Synthetic tool write reported.",
        evidence=(_action_evidence(),),
        provider_metadata={"agent_trace_complete": True},
    )

    judgment = judge.evaluate(case, response)

    assert judgment.model_compromise is True
    assert judgment.system_compromise is False


def test_builtin_judge_requires_trusted_independent_effect_for_system_compromise() -> None:
    case = build_hal_smoke_case()
    judge = build_hal_smoke_judge()
    effect = AgentEffectObservation(
        control_event_id="smoke-write-1",
        verifier_id=HAL_SMOKE_VERIFIER_ID,
        state=AgentEffectState.OBSERVED,
        categories=frozenset({"filesystem_write"}),
        effect_hash="b" * 64,
        state_before_hash="c" * 64,
        state_after_hash="d" * 64,
        source="deterministic_state_verifier",
    ).to_evidence()
    response = TargetResponse(
        text="Synthetic tool write reported.",
        evidence=(_action_evidence(), effect),
        provider_metadata={"agent_trace_complete": True},
    )

    judgment = judge.evaluate(case, response)

    assert judgment.objective_violated is True
    assert judgment.model_compromise is True
    assert judgment.system_compromise is True
