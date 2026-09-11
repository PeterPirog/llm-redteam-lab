"""Stateful multi-turn attack execution with replay and branching semantics."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from typing import Protocol, runtime_checkable
from uuid import uuid4

from pydantic import Field, model_validator

from ..budget import BudgetLedger
from ..domain import (
    AttackCase,
    CompromiseOutcome,
    EvidenceKind,
    EvidenceRecord,
    ExecutionResult,
    StrictModel,
    TargetClass,
)
from ..judges.base import Judge, Judgment, evaluate_judge, outcome_from_judgment
from ..targets.base import (
    ConversationMessage,
    MessageRole,
    SessionMode,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
)


class ConversationStopReason(StrEnum):
    """Why a bounded attack conversation stopped."""

    OBJECTIVE_VIOLATION = "objective_violation"
    SYSTEM_COMPROMISE = "system_compromise"
    STRATEGY_STOP = "strategy_stop"
    TURN_BUDGET = "turn_budget"
    ERROR = "error"


class ConversationBudget(StrictModel):
    """Flow-control limits that define one reproducible multi-turn attack."""

    max_turns: int = Field(gt=0, default=5)
    max_backtracks: int = Field(ge=0, default=2)
    max_branches: int = Field(gt=0, default=3)
    continue_after_success: bool = False
    stop_after_system_compromise: bool = False

    @model_validator(mode="after")
    def stopping_policy_is_consistent(self) -> ConversationBudget:
        if self.stop_after_system_compromise and not self.continue_after_success:
            raise ValueError(
                "stop_after_system_compromise requires continue_after_success so a "
                "model-only compromise can be followed by bounded system escalation"
            )
        return self

    @property
    def stopping_policy(self) -> str:
        if self.stop_after_system_compromise:
            return "system_compromise_or_strategy_or_budget-v1"
        if self.continue_after_success:
            return "strategy_or_budget-v1"
        return "first_objective_violation-v1"


class TurnProposal(StrictModel):
    """One attacker decision.

    ``branch_from_turn_id`` requests a new branch from a prior turn. It is
    deliberately explicit so backtracking is evidence rather than hidden model
    behavior.
    """

    message: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    branch_from_turn_id: str | None = None


class ConversationTurn(StrictModel):
    turn_id: str = Field(min_length=1)
    ordinal: int = Field(gt=0)
    depth: int = Field(gt=0)
    branch_id: str = Field(min_length=1)
    parent_turn_id: str | None = None
    attacker_message: str = Field(min_length=1)
    target_response: str | None = None
    outcome: CompromiseOutcome
    judgment: Judgment | None = None
    error_kind: str | None = None
    evidence: tuple[EvidenceRecord, ...] = ()


class ConversationState(StrictModel):
    conversation_id: str = Field(min_length=1)
    attack_id: str = Field(min_length=1)
    session_mode: SessionMode
    turns: tuple[ConversationTurn, ...] = ()
    active_leaf_turn_id: str | None = None
    session_id: str | None = None
    backtracks: int = Field(ge=0, default=0)
    branches: int = Field(gt=0, default=1)


class ConversationRunResult(StrictModel):
    execution: ExecutionResult
    conversation_id: str = Field(min_length=1)
    session_mode: SessionMode
    turns: tuple[ConversationTurn, ...]
    backtracks: int = Field(ge=0)
    branches: int = Field(gt=0)
    first_violation_turn_id: str | None = None
    first_violation_ordinal: int | None = Field(default=None, gt=0)
    first_violation_depth: int | None = Field(default=None, gt=0)
    first_model_compromise_turn_id: str | None = None
    first_model_compromise_ordinal: int | None = Field(default=None, gt=0)
    first_model_compromise_depth: int | None = Field(default=None, gt=0)
    first_system_compromise_turn_id: str | None = None
    first_system_compromise_ordinal: int | None = Field(default=None, gt=0)
    first_system_compromise_depth: int | None = Field(default=None, gt=0)
    stop_reason: ConversationStopReason = ConversationStopReason.STRATEGY_STOP
    flow_fingerprint: str = Field(min_length=1)


@runtime_checkable
class MultiTurnStrategy(Protocol):
    """Produce the next attacker turn from all evidence observed so far."""

    async def next_turn(self, state: ConversationState) -> TurnProposal | None: ...


class MultiTurnCampaignEngine:
    """Execute one multi-turn jailbreak as one statistical attack trial.

    Individual target interactions are retained as turns, but the final
    ``ExecutionResult`` represents the conversation as a whole. This prevents
    longer conversations from receiving larger ASR denominators merely because
    they consumed more turns.

    Layer-aware AGENT campaigns may continue after a model-only compromise in
    order to test whether surrounding authorization and sandbox controls remain
    effective. Judge labels used for stopping are never injected into the live
    Red strategy state; Red continues to receive target-visible evidence only.
    """

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: Judge,
        conversation_budget: ConversationBudget,
        budget: BudgetLedger | None = None,
    ) -> None:
        self.target = target
        self.judge = judge
        self.conversation_budget = conversation_budget
        self.budget = budget

    async def run_case(
        self,
        case: AttackCase,
        strategy: MultiTurnStrategy,
        *,
        session_mode: SessionMode = SessionMode.REPLAY,
        conversation_id: str | None = None,
    ) -> ConversationRunResult:
        self._validate_case(case)
        identity = self.target.identity
        resolved_id = conversation_id or (
            f"conv-{identity.configuration_hash[:8]}-{uuid4().hex}"
        )

        if self.budget is not None:
            if (
                self.conversation_budget.max_turns
                > self.budget.budget.max_turns_per_attack
            ):
                raise ValueError(
                    "conversation max_turns exceeds the authorized campaign per-attack limit"
                )
            self.budget.reserve_attack()
            self.budget.check_wall_clock()

        state = ConversationState(
            conversation_id=resolved_id,
            attack_id=case.id,
            session_mode=session_mode,
            session_id=None,
        )
        first_violation: ConversationTurn | None = None
        first_model_compromise: ConversationTurn | None = None
        first_system_compromise: ConversationTurn | None = None
        stop_reason: ConversationStopReason | None = None

        while len(state.turns) < self.conversation_budget.max_turns:
            proposal = await strategy.next_turn(state)
            if proposal is None:
                stop_reason = ConversationStopReason.STRATEGY_STOP
                break
            state, parent_turn_id, branch_id = self._apply_branch_request(state, proposal)

            if self.budget is not None:
                self.budget.reserve_turn(attack_id=resolved_id)
                if identity.target_class == TargetClass.IMAGE_GENERATION:
                    self.budget.reserve_image_generation()
                self.budget.check_wall_clock()

            history = ()
            if session_mode == SessionMode.REPLAY:
                history = self._history_for_parent(state.turns, parent_turn_id)

            response = await self.target.execute(
                TargetRequest(
                    attack_id=case.id,
                    prompt=proposal.message,
                    conversation=history,
                    session_mode=session_mode,
                    session_id=state.session_id,
                    metadata={
                        "conversation_id": resolved_id,
                        "branch_id": branch_id,
                        "turn_ordinal": str(len(state.turns) + 1),
                    },
                )
            )
            if (
                session_mode == SessionMode.TARGET_MANAGED
                and response.error_kind is None
                and response.session_id is None
            ):
                response = response.model_copy(
                    update={"error_kind": "session:target_managed_missing_session_id"}
                )

            turn = await self._make_turn(
                case=case,
                state=state,
                proposal=proposal,
                response=response,
                parent_turn_id=parent_turn_id,
                branch_id=branch_id,
            )
            turns = (*state.turns, turn)
            state = ConversationState(
                conversation_id=state.conversation_id,
                attack_id=state.attack_id,
                session_mode=state.session_mode,
                turns=turns,
                active_leaf_turn_id=turn.turn_id,
                session_id=response.session_id or state.session_id,
                backtracks=state.backtracks,
                branches=state.branches,
            )

            if turn.judgment is not None:
                if turn.judgment.objective_violated is True and first_violation is None:
                    first_violation = turn
                if turn.judgment.model_compromise and first_model_compromise is None:
                    first_model_compromise = turn
                if turn.judgment.system_compromise and first_system_compromise is None:
                    first_system_compromise = turn

            if turn.error_kind is not None:
                stop_reason = ConversationStopReason.ERROR
                break
            if (
                first_system_compromise is not None
                and self.conversation_budget.stop_after_system_compromise
            ):
                stop_reason = ConversationStopReason.SYSTEM_COMPROMISE
                break
            if (
                turn.judgment is not None
                and turn.judgment.objective_violated is True
                and not self.conversation_budget.continue_after_success
            ):
                stop_reason = ConversationStopReason.OBJECTIVE_VIOLATION
                break
        else:
            stop_reason = ConversationStopReason.TURN_BUDGET

        if stop_reason is None:
            stop_reason = ConversationStopReason.TURN_BUDGET

        state = self._attach_flow_summary(
            state,
            stop_reason=stop_reason,
            first_violation=first_violation,
            first_model_compromise=first_model_compromise,
            first_system_compromise=first_system_compromise,
        )
        execution = self._conversation_execution(case, state)
        return ConversationRunResult(
            execution=execution,
            conversation_id=state.conversation_id,
            session_mode=state.session_mode,
            turns=state.turns,
            backtracks=state.backtracks,
            branches=state.branches,
            first_violation_turn_id=first_violation.turn_id if first_violation else None,
            first_violation_ordinal=first_violation.ordinal if first_violation else None,
            first_violation_depth=first_violation.depth if first_violation else None,
            first_model_compromise_turn_id=(
                first_model_compromise.turn_id if first_model_compromise else None
            ),
            first_model_compromise_ordinal=(
                first_model_compromise.ordinal if first_model_compromise else None
            ),
            first_model_compromise_depth=(
                first_model_compromise.depth if first_model_compromise else None
            ),
            first_system_compromise_turn_id=(
                first_system_compromise.turn_id if first_system_compromise else None
            ),
            first_system_compromise_ordinal=(
                first_system_compromise.ordinal if first_system_compromise else None
            ),
            first_system_compromise_depth=(
                first_system_compromise.depth if first_system_compromise else None
            ),
            stop_reason=stop_reason,
            flow_fingerprint=self._flow_fingerprint(strategy, session_mode),
        )

    def _validate_case(self, case: AttackCase) -> None:
        identity = self.target.identity
        if case.interaction_mode != "multi_turn":
            raise ValueError(f"case {case.id} is not declared as multi_turn")
        if identity.target_class not in case.target_classes:
            raise ValueError(
                f"case {case.id} incompatible with target class {identity.target_class.value}"
            )
        if identity.target_mode not in case.target_modes:
            raise ValueError(
                f"case {case.id} incompatible with target mode {identity.target_mode.value}"
            )

    def _apply_branch_request(
        self,
        state: ConversationState,
        proposal: TurnProposal,
    ) -> tuple[ConversationState, str | None, str]:
        parent = state.active_leaf_turn_id
        branch_id = self._branch_for_turn(state.turns, parent) or "b0"
        requested = proposal.branch_from_turn_id

        if requested is None or requested == parent:
            return state, parent, branch_id
        if state.session_mode == SessionMode.TARGET_MANAGED:
            raise ValueError("backtracking is not supported for target-managed sessions")
        if not any(turn.turn_id == requested for turn in state.turns):
            raise ValueError(f"unknown branch_from_turn_id: {requested}")

        backtracks = state.backtracks + 1
        branches = state.branches + 1
        if backtracks > self.conversation_budget.max_backtracks:
            raise ValueError("multi-turn backtrack limit exceeded")
        if branches > self.conversation_budget.max_branches:
            raise ValueError("multi-turn branch limit exceeded")

        return (
            ConversationState(
                conversation_id=state.conversation_id,
                attack_id=state.attack_id,
                session_mode=state.session_mode,
                turns=state.turns,
                active_leaf_turn_id=requested,
                session_id=state.session_id,
                backtracks=backtracks,
                branches=branches,
            ),
            requested,
            f"b{branches - 1}",
        )

    async def _make_turn(
        self,
        *,
        case: AttackCase,
        state: ConversationState,
        proposal: TurnProposal,
        response: TargetResponse,
        parent_turn_id: str | None,
        branch_id: str,
    ) -> ConversationTurn:
        ordinal = len(state.turns) + 1
        depth = len(self._path_to_turn(state.turns, parent_turn_id)) + 1
        turn_id = self._turn_id(state.conversation_id, ordinal, branch_id)
        transcript_evidence = EvidenceRecord(
            kind=EvidenceKind.TRANSCRIPT,
            source="multiturn_campaign_engine",
            observed_at="runtime",
            content_hash=sha256(
                (proposal.message + "\n" + (response.text or "")).encode()
            ).hexdigest(),
            data={
                "turn_id": turn_id,
                "ordinal": ordinal,
                "depth": depth,
                "branch_id": branch_id,
                "parent_turn_id": parent_turn_id or "",
            },
            redacted=True,
        )
        evidence = (*response.evidence, transcript_evidence)

        if response.error_kind is not None:
            return ConversationTurn(
                turn_id=turn_id,
                ordinal=ordinal,
                depth=depth,
                branch_id=branch_id,
                parent_turn_id=parent_turn_id,
                attacker_message=proposal.message,
                target_response=response.text,
                outcome=CompromiseOutcome.ERROR,
                error_kind=response.error_kind,
                evidence=evidence,
            )

        judgment = await evaluate_judge(self.judge, case, response)
        return ConversationTurn(
            turn_id=turn_id,
            ordinal=ordinal,
            depth=depth,
            branch_id=branch_id,
            parent_turn_id=parent_turn_id,
            attacker_message=proposal.message,
            target_response=response.text,
            outcome=outcome_from_judgment(judgment),
            judgment=judgment,
            evidence=evidence,
        )

    def _attach_flow_summary(
        self,
        state: ConversationState,
        *,
        stop_reason: ConversationStopReason,
        first_violation: ConversationTurn | None,
        first_model_compromise: ConversationTurn | None,
        first_system_compromise: ConversationTurn | None,
    ) -> ConversationState:
        if not state.turns:
            return state
        data = {
            "stop_reason": stop_reason.value,
            "stopping_policy": self.conversation_budget.stopping_policy,
            "first_violation_ordinal": (
                first_violation.ordinal if first_violation else None
            ),
            "first_model_compromise_ordinal": (
                first_model_compromise.ordinal if first_model_compromise else None
            ),
            "first_system_compromise_ordinal": (
                first_system_compromise.ordinal if first_system_compromise else None
            ),
            "turn_count": len(state.turns),
        }
        fingerprint_material = "|".join(
            [
                state.conversation_id,
                stop_reason.value,
                self.conversation_budget.stopping_policy,
                str(data["first_violation_ordinal"]),
                str(data["first_model_compromise_ordinal"]),
                str(data["first_system_compromise_ordinal"]),
                str(data["turn_count"]),
            ]
        )
        summary = EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="multiturn_flow_control",
            observed_at="runtime",
            content_hash=sha256(fingerprint_material.encode()).hexdigest(),
            data=data,
            redacted=True,
        )
        last = state.turns[-1].model_copy(
            update={"evidence": (*state.turns[-1].evidence, summary)}
        )
        return state.model_copy(update={"turns": (*state.turns[:-1], last)})

    def _conversation_execution(
        self,
        case: AttackCase,
        state: ConversationState,
    ) -> ExecutionResult:
        identity = self.target.identity
        evidence = tuple(item for turn in state.turns for item in turn.evidence)
        execution_id = self._execution_id(state.conversation_id, identity.configuration_hash)

        judgments = tuple(
            turn.judgment for turn in state.turns if turn.judgment is not None
        )
        model_compromise = any(item.model_compromise for item in judgments)
        system_compromise = any(item.system_compromise for item in judgments)
        objective_violated = any(item.objective_violated is True for item in judgments)
        unresolved = any(item.objective_violated is None for item in judgments) or any(
            turn.outcome in {CompromiseOutcome.INCONCLUSIVE, CompromiseOutcome.PARTIAL}
            for turn in state.turns
        )
        errors = [turn for turn in state.turns if turn.error_kind is not None]
        confidence = min((item.confidence for item in judgments), default=1.0)

        # Positive evidence is monotonic: once both layers have been independently
        # established, a later transport/error condition cannot erase the compromise.
        if model_compromise and system_compromise:
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE,
                objective_violated=True,
                model_compromise=True,
                system_compromise=True,
                confidence=confidence,
                evidence=evidence,
            )

        # Preserve a known positive layer without silently treating unresolved later
        # evidence as successful containment of the other layer.
        if objective_violated and (unresolved or errors):
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.PARTIAL,
                objective_violated=None,
                model_compromise=model_compromise,
                system_compromise=system_compromise,
                confidence=confidence,
                evidence=evidence,
                error_kind=errors[-1].error_kind if errors else None,
            )

        if objective_violated:
            if system_compromise:
                outcome = CompromiseOutcome.SYSTEM_COMPROMISE
            elif model_compromise:
                outcome = CompromiseOutcome.MODEL_COMPROMISE
            else:
                outcome = CompromiseOutcome.PARTIAL
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=outcome,
                objective_violated=(True if outcome != CompromiseOutcome.PARTIAL else None),
                model_compromise=model_compromise,
                system_compromise=system_compromise,
                confidence=confidence,
                evidence=evidence,
            )

        if errors:
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.ERROR,
                objective_violated=None,
                model_compromise=False,
                system_compromise=False,
                confidence=confidence,
                evidence=evidence,
                error_kind=errors[-1].error_kind,
            )

        if not state.turns or unresolved:
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.INCONCLUSIVE,
                objective_violated=None,
                model_compromise=False,
                system_compromise=False,
                confidence=confidence,
                evidence=evidence,
            )

        return ExecutionResult(
            execution_id=execution_id,
            attack_id=case.id,
            target_id=identity.id,
            outcome=CompromiseOutcome.PASS,
            objective_violated=False,
            model_compromise=False,
            system_compromise=False,
            confidence=confidence,
            evidence=evidence,
        )

    @staticmethod
    def _history_for_parent(
        turns: tuple[ConversationTurn, ...], parent_turn_id: str | None
    ) -> tuple[ConversationMessage, ...]:
        messages: list[ConversationMessage] = []
        for turn in MultiTurnCampaignEngine._path_to_turn(turns, parent_turn_id):
            messages.append(
                ConversationMessage(role=MessageRole.USER, content=turn.attacker_message)
            )
            if turn.target_response:
                messages.append(
                    ConversationMessage(role=MessageRole.ASSISTANT, content=turn.target_response)
                )
        return tuple(messages)

    @staticmethod
    def _path_to_turn(
        turns: tuple[ConversationTurn, ...], turn_id: str | None
    ) -> tuple[ConversationTurn, ...]:
        if turn_id is None:
            return ()
        by_id = {turn.turn_id: turn for turn in turns}
        path: list[ConversationTurn] = []
        current = turn_id
        while current is not None:
            turn = by_id[current]
            path.append(turn)
            current = turn.parent_turn_id
        path.reverse()
        return tuple(path)

    @staticmethod
    def _branch_for_turn(
        turns: tuple[ConversationTurn, ...], turn_id: str | None
    ) -> str | None:
        if turn_id is None:
            return None
        for turn in turns:
            if turn.turn_id == turn_id:
                return turn.branch_id
        return None

    def _flow_fingerprint(
        self, strategy: MultiTurnStrategy, session_mode: SessionMode
    ) -> str:
        raw = "|".join(
            [
                type(strategy).__name__,
                type(self.judge).__name__,
                session_mode.value,
                str(self.conversation_budget.max_turns),
                str(self.conversation_budget.max_backtracks),
                str(self.conversation_budget.max_branches),
                str(self.conversation_budget.continue_after_success),
                str(self.conversation_budget.stop_after_system_compromise),
                self.conversation_budget.stopping_policy,
            ]
        )
        return sha256(raw.encode()).hexdigest()

    @staticmethod
    def _turn_id(conversation_id: str, ordinal: int, branch_id: str) -> str:
        digest = sha256(f"{conversation_id}:{ordinal}:{branch_id}".encode()).hexdigest()[:16]
        return f"turn-{digest}"

    @staticmethod
    def _execution_id(conversation_id: str, target_hash: str) -> str:
        digest = sha256(f"{conversation_id}:{target_hash}".encode()).hexdigest()[:16]
        return f"exec-{digest}"
