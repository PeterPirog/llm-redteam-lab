from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from llm_redteam.domain import CompromiseOutcome, ExecutionResult
from llm_redteam.telemetry import RedTeamTelemetry
from llm_redteam.targets.base import SessionMode
from llm_redteam.targets.mock_multiturn import EscalatingVaultTarget


def _telemetry():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return RedTeamTelemetry(provider.get_tracer("llm-redteam-test")), exporter


def test_security_spans_record_structure_without_prompt_content() -> None:
    telemetry, exporter = _telemetry()
    target = EscalatingVaultTarget().identity

    with telemetry.campaign_span(campaign_id="campaign-otel", target=target):
        with telemetry.attack_span(
            attack_instance_id="attack-1",
            case_id="case-1",
            attack_family="multi_turn_escalation",
            generation=0,
            interaction_mode="multi_turn",
        ):
            with telemetry.turn_span(
                conversation_id="conv-1",
                ordinal=2,
                depth=2,
                branch_id="b0",
                session_mode=SessionMode.REPLAY,
            ) as span:
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
