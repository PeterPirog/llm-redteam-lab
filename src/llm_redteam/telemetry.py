"""OpenTelemetry helpers for security evaluation without raw prompt capture."""

from __future__ import annotations

from contextlib import AbstractContextManager

from opentelemetry.trace import Span, Status, StatusCode, Tracer

from .agent_actions import AgentActionObservation
from .domain import CompromiseOutcome, ExecutionResult, TargetIdentity
from .targets.base import SessionMode


class RedTeamTelemetry:
    """Create stable security spans while keeping content capture opt-in."""

    def __init__(self, tracer: Tracer) -> None:
        self.tracer = tracer

    def campaign_span(
        self,
        *,
        campaign_id: str,
        target: TargetIdentity,
    ) -> AbstractContextManager[Span]:
        return self.tracer.start_as_current_span(
            "llm_redteam.campaign",
            attributes={
                "llm_redteam.campaign.id": campaign_id,
                "llm_redteam.target.id": target.id,
                "llm_redteam.target.class": target.target_class.value,
                "llm_redteam.target.mode": target.target_mode.value,
                "llm_redteam.target.configuration_hash": target.configuration_hash,
            },
        )

    def attack_span(
        self,
        *,
        attack_instance_id: str,
        case_id: str,
        attack_family: str,
        generation: int,
        interaction_mode: str,
    ) -> AbstractContextManager[Span]:
        return self.tracer.start_as_current_span(
            "llm_redteam.attack",
            attributes={
                "llm_redteam.attack.instance_id": attack_instance_id,
                "llm_redteam.attack.case_id": case_id,
                "llm_redteam.attack.family": attack_family,
                "llm_redteam.attack.generation": generation,
                "llm_redteam.attack.interaction_mode": interaction_mode,
            },
        )

    def turn_span(
        self,
        *,
        conversation_id: str,
        ordinal: int,
        depth: int,
        branch_id: str,
        session_mode: SessionMode,
    ) -> AbstractContextManager[Span]:
        return self.tracer.start_as_current_span(
            "llm_redteam.turn",
            attributes={
                "llm_redteam.conversation.id": conversation_id,
                "llm_redteam.turn.ordinal": ordinal,
                "llm_redteam.turn.depth": depth,
                "llm_redteam.turn.branch_id": branch_id,
                "llm_redteam.session.mode": session_mode.value,
            },
        )

    def target_span(
        self,
        *,
        target: TargetIdentity,
        operation_name: str = "chat",
    ) -> AbstractContextManager[Span]:
        return self.tracer.start_as_current_span(
            "llm_redteam.target.request",
            attributes={
                "gen_ai.operation.name": operation_name,
                "gen_ai.request.model": target.model,
                "llm_redteam.target.id": target.id,
                "llm_redteam.target.provider": target.provider,
            },
        )

    def image_generation_span(
        self,
        *,
        target: TargetIdentity,
    ) -> AbstractContextManager[Span]:
        """Trace image generation without recording prompt or image content."""

        return self.tracer.start_as_current_span(
            "llm_redteam.image.generate",
            attributes={
                "gen_ai.operation.name": "generate_content",
                "gen_ai.request.model": target.model,
                "gen_ai.output.type": "image",
                "llm_redteam.target.id": target.id,
                "llm_redteam.target.provider": target.provider,
            },
        )

    def agent_span(
        self,
        *,
        target: TargetIdentity,
        session_id: str,
    ) -> AbstractContextManager[Span]:
        """Trace one agent invocation without recording message content."""

        return self.tracer.start_as_current_span(
            "llm_redteam.agent.invoke",
            attributes={
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.request.model": target.model,
                "llm_redteam.target.id": target.id,
                "llm_redteam.target.provider": target.provider,
                "llm_redteam.agent.session_id_hash": self._hash_identifier(session_id),
            },
        )

    def tool_span(
        self,
        observation: AgentActionObservation,
    ) -> AbstractContextManager[Span]:
        """Trace one observed tool call without exporting arguments or results."""

        return self.tracer.start_as_current_span(
            "llm_redteam.tool.execute",
            attributes={
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": observation.tool,
                "gen_ai.tool.call.id": observation.control_event_id,
                "llm_redteam.control.event_id": observation.control_event_id,
                "llm_redteam.agent.action.phase": observation.phase.value,
                "llm_redteam.agent.action.categories": sorted(observation.categories),
                "llm_redteam.agent.action.input_hash": observation.input_hash,
            },
        )

    def judge_span(self, *, judge_type: str) -> AbstractContextManager[Span]:
        return self.tracer.start_as_current_span(
            "llm_redteam.judge",
            attributes={"llm_redteam.judge.type": judge_type},
        )

    @staticmethod
    def annotate_execution(span: Span, result: ExecutionResult) -> None:
        span.set_attribute("llm_redteam.execution.id", result.execution_id)
        span.set_attribute("llm_redteam.execution.outcome", result.outcome.value)
        span.set_attribute("llm_redteam.execution.model_compromise", result.model_compromise)
        span.set_attribute("llm_redteam.execution.system_compromise", result.system_compromise)
        span.set_attribute("llm_redteam.execution.confidence", result.confidence)
        if result.objective_violated is not None:
            span.set_attribute(
                "llm_redteam.execution.objective_violated",
                result.objective_violated,
            )
        if result.outcome == CompromiseOutcome.ERROR:
            span.set_status(Status(StatusCode.ERROR, result.error_kind or "execution error"))
        else:
            span.set_status(Status(StatusCode.OK))

    @staticmethod
    def _hash_identifier(value: str) -> str:
        from hashlib import sha256

        return sha256(value.encode()).hexdigest()
