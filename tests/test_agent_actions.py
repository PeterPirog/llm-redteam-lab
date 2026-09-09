from llm_redteam.agent_actions import (
    AgentActionObservation,
    AgentActionPhase,
    canonical_json_hash,
    classify_agent_action,
)


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
