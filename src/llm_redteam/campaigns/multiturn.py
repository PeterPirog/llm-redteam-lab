"""Stateful multi-turn attack execution with replay and branching semantics."""

from __future__ import annotations

from hashlib import sha256
from typing import Protocol, runtime_checkable
from uuid import uuid4

from pydantic import Field

from ..budget import BudgetLedger
from ..domain import (
    AttackCase,
    CompromiseOutcome,
    EvidenceKind,
    EvidenceRecord,
    ExecutionResult,
    StrictModel,
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


class ConversationBudget(StrictModel):
    """Flow-control limits that define one reproducible multi-turn attack."""

    max_turns: int = Field(gt=0, default=5)
    max_backtracks: int = Field(ge=0, default=2)
    max_branches: int = Field(gt=0, default=3)
    continue_after_success: bool = False


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
            session_id=resolved_id if session_mode == SessionMode.TARGET_MANAGED else None,
        )
        first_violation: ConversationTurn | None = None

        while len(state.turns) < self.conversation_budget.max_turns:
            proposal = await strategy.next_turn(state)
            if proposal is None:
                break
            state, parent_turn_id, branch_id = self._apply_branch_request(state, proposal)

            if self.budget is not None:
                self.budget.reserve_turn(attack_id=resolved_id)
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

            if turn.judgment is not None and turn.judgment.objective_violated is True:
                if first_violation is None:
                    first_violation = turn
                if not self.conversation_budget.continue_after_success:
                    break
            if turn.error_kind is not None:
                break

        execution = self._conversation_execution(case, state, first_violation)
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

    def _conversation_execution(
        self,
        case: AttackCase,
        state: ConversationState,
        first_violation: ConversationTurn | None,
    ) -> ExecutionResult:
        identity = self.target.identity
        evidence = tuple(item for turn in state.turns for item in turn.evidence)
        execution_id = self._execution_id(state.conversation_id, identity.configuration_hash)

        if first_violation is not None and first_violation.judgment is not None:
            judgment = first_violation.judgment
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=outcome_from_judgment(judgment),
                objective_violated=True,
                model_compromise=judgment.model_compromise,
                system_compromise=judgment.system_compromise,
                confidence=judgment.confidence,
                evidence=evidence,
            )

        errors = [turn for turn in state.turns if turn.error_kind is not None]
        if errors:
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.ERROR,
                objective_violated=None,
                model_compromise=False,
                system_compromise=False,
                confidence=1.0,
                evidence=evidence,
                error_kind=errors[-1].error_kind,
            )

        unresolved = [
            turn
            for turn in state.turns
            if turn.outcome in {CompromiseOutcome.INCONCLUSIVE, CompromiseOutcome.PARTIAL}
        ]
        if not state.turns or unresolved:
            return ExecutionResult(
                execution_id=execution_id,
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.INCONCLUSIVE,
                objective_violated=None,
                model_compromise=False,
                system_compromise=False,
                confidence=1.0,
                evidence=evidence,
            )

        confidence = min(
            turn.judgment.confidence
            for turn in state.turns
            if turn.judgment is not None
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
