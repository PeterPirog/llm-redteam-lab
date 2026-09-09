from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from llm_redteam.agent_actions import AgentActionObservation, AgentActionPhase
from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.targets.base import SessionMode
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget
from llm_redteam.telemetry import RedTeamTelemetry


def _telemetry():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return RedTeamTelemetry(provider.get_tracer("llm-redteam-test")), exporter


def test_security_spans_record_structure_without_prompt_content() -> None:
    telemetry, exporter = _telemetry()
    target = EscalatingVaultTarget().identity

    with (
        telemetry.campaign_span(campaign_id="campaign-otel", target=target),
        telemetry.attack_span(
            attack_instance_id="attack-1",
            case_id="case-1",
            attack_family="multi_turn_escalation",
            generation=0,
            interaction_mode="multi_turn",
        ),
        telemetry.turn_span(
            conversation_id="conv-1",
            ordinal=2,
            depth=2,
            branch_id="b0",
            session_mode=SessionMode.REPLAY,
        ) as span,
    ):
        result = ExecutionResult(
            execution_id="exec-1",
            attack_id="case-1",
            target_id=target.id,
            outcome=CompromiseOutcome.MODEL_COMPROMISE,
            objective_violated=True,
            model_compromise=True,
            system_compromise=False,
            confidence=1.0,
        )
        telemetry.annotate_execution(span, result)

    spans = exporter.get_finished_spans()
    names = {span.name for span in spans}
    assert names == {
        "llm_redteam.campaign",
        "llm_redteam.attack",
        "llm_redteam.turn",
    }

    serialized_attributes = " ".join(
        str(value)
        for finished in spans
        for value in finished.attributes.values()
    )
    assert "RT_CANARY" not in serialized_attributes
    assert "prompt" not in serialized_attributes.casefold()


def test_target_span_uses_genai_operation_metadata_only() -> None:
    telemetry, exporter = _telemetry()
    target = EscalatingVaultTarget().identity

    with telemetry.target_span(target=target):
        pass

    span = exporter.get_finished_spans()[0]
    assert span.attributes["gen_ai.operation.name"] == "chat"
    assert span.attributes["gen_ai.request.model"] == target.model
    assert "llm_redteam.target.id" in span.attributes


def test_agent_and_tool_spans_use_genai_operations_without_raw_tool_content() -> None:
    telemetry, exporter = _telemetry()
    target = EscalatingVaultTarget().identity
    observation = AgentActionObservation(
        control_event_id="call-1",
        session_id="secret-session-id",
        message_id="message-1",
        tool="bash",
        phase=AgentActionPhase.EXECUTED,
        categories=frozenset({"tool_call", "shell"}),
        input_hash="a" * 64,
        output_hash="b" * 64,
        source="test",
    )

    with telemetry.agent_span(target=target, session_id=observation.session_id):
        with telemetry.tool_span(observation):
            pass

    spans = {span.name: span for span in exporter.get_finished_spans()}
    agent = spans["llm_redteam.agent.invoke"]
    tool = spans["llm_redteam.tool.execute"]

    assert agent.attributes["gen_ai.operation.name"] == "invoke_agent"
    assert tool.attributes["gen_ai.operation.name"] == "execute_tool"
    assert tool.attributes["gen_ai.tool.name"] == "bash"
    assert tool.attributes["gen_ai.tool.call.id"] == "call-1"

    serialized = " ".join(
        str(value)
        for span in spans.values()
        for value in span.attributes.values()
    )
    assert "secret-session-id" not in serialized
    assert "tool arguments" not in serialized
