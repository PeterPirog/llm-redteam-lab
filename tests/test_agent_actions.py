import pytest

from llm_redteam.agent_actions import (
    AgentActionObservation,
    AgentActionPhase,
    AgentAuthorizationDecision,
    AgentAuthorizationObservation,
    AgentEffectObservation,
    AgentEffectState,
    canonical_json_hash,
    classify_agent_action,
)
from llm_redteam.domain import EvidenceKind


def test_shell_git_push_is_classified_as_shell_network_and_git_push() -> None:
    categories = classify_agent_action(
        "bash",
        {"command": "git status && git push origin main"},
    )

    assert {"tool_call", "shell", "git_push", "network"}.issubset(categories)


def test_windows_path_outside_workspace_is_classified_without_host_os_dependency() -> None:
    categories = classify_agent_action(
        "read",
        {"filePath": r"C:\\Users\\Peter\\.ssh\\id_rsa"},
        workspace_root=r"C:\\work\\llm-redteam-lab",
    )

    assert "filesystem_read" in categories
    assert "external_path" in categories


def test_relative_path_is_not_external() -> None:
    categories = classify_agent_action(
        "edit",
        {"filePath": "src/app.py"},
        workspace_root=r"C:\\work\\llm-redteam-lab",
    )

    assert "filesystem_write" in categories
    assert "external_path" not in categories


def test_agent_action_evidence_contains_hashes_not_raw_tool_payload() -> None:
    raw_input = {"command": "synthetic-sensitive-command RT_CANARY_001"}
    raw_output = "synthetic-sensitive-output"
    observation = AgentActionObservation(
        control_event_id="call-1",
        session_id="session-1",
        message_id="message-1",
        tool="bash",
        phase=AgentActionPhase.EXECUTED,
        categories=frozenset({"tool_call", "shell"}),
        input_hash=canonical_json_hash(raw_input),
        output_hash=canonical_json_hash(raw_output),
        source="test",
    )

    evidence = observation.to_evidence()
    serialized = evidence.model_dump_json()

    assert raw_input["command"] not in serialized
    assert raw_output not in serialized
    assert evidence.data["phase"] == "executed"
    assert evidence.data["control_event_id"] == "call-1"


def test_authorization_decision_is_a_separate_guardrail_event() -> None:
    observation = AgentAuthorizationObservation(
        control_event_id="call-1",
        decision=AgentAuthorizationDecision.DENIED,
        control_id="workspace-policy-v1",
        decision_hash="a" * 64,
        source="sandbox_authorizer",
    )

    evidence = observation.to_evidence()

    assert evidence.kind == EvidenceKind.GUARDRAIL
    assert evidence.data["decision"] == "denied"
    assert evidence.data["control_id"] == "workspace-policy-v1"


def test_observed_effect_requires_fingerprint_and_is_system_state_evidence() -> None:
    with pytest.raises(ValueError, match="requires effect_hash"):
        AgentEffectObservation(
            control_event_id="call-1",
            verifier_id="workspace-monitor-v1",
            state=AgentEffectState.OBSERVED,
            categories=frozenset({"filesystem_write", "external_path"}),
        )

    observation = AgentEffectObservation(
        control_event_id="call-1",
        verifier_id="workspace-monitor-v1",
        state=AgentEffectState.OBSERVED,
        categories=frozenset({"filesystem_write", "external_path"}),
        effect_hash="b" * 64,
        state_before_hash="c" * 64,
        state_after_hash="d" * 64,
    )
    evidence = observation.to_evidence()

    assert evidence.kind == EvidenceKind.SYSTEM_STATE
    assert evidence.data["state"] == "observed"
    assert evidence.data["verifier_id"] == "workspace-monitor-v1"
    assert "filesystem_write" in evidence.data["categories"]
