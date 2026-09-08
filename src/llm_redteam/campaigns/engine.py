"""Minimal end-to-end campaign loop used before adaptive model inference."""

from __future__ import annotations

from hashlib import sha256

from ..budget import BudgetLedger
from ..domain import AttackCase, CompromiseOutcome, EvidenceKind, EvidenceRecord, ExecutionResult
from ..judges.base import outcome_from_judgment
from ..judges.deterministic import DeterministicJudge
from ..targets.base import TargetAdapter, TargetRequest


def render_case_prompt(case: AttackCase) -> str:
    """Render a text/template corpus case using explicit variables only."""

    if case.payload.text is not None:
        return case.payload.text
    if case.payload.template is None:
        raise ValueError(f"case {case.id} is not a prompt-based case")

    rendered = case.payload.template
    for name, value in case.variables.items():
        rendered = rendered.replace("{{" + name + "}}", str(value))
    if "{{" in rendered or "}}" in rendered:
        raise ValueError(f"case {case.id} contains unresolved template variables")
    return rendered


class CampaignEngine:
    """Execute normalized cases against one target with an independent judge."""

    def __init__(
        self,
        *,
        target: TargetAdapter,
        judge: DeterministicJudge,
        budget: BudgetLedger | None = None,
    ) -> None:
        self.target = target
        self.judge = judge
        self.budget = budget

    async def run_case(self, case: AttackCase) -> ExecutionResult:
        if self.budget is not None:
            self.budget.reserve_attack()
            self.budget.check_wall_clock()

        identity = self.target.identity
        if identity.target_class not in case.target_classes:
            raise ValueError(
                f"case {case.id} incompatible with target class {identity.target_class.value}"
            )
        if identity.target_mode not in case.target_modes:
            raise ValueError(
                f"case {case.id} incompatible with target mode {identity.target_mode.value}"
            )

        prompt = render_case_prompt(case)
        response = await self.target.execute(TargetRequest(attack_id=case.id, prompt=prompt))

        if response.error_kind:
            return ExecutionResult(
                execution_id=self._execution_id(case.id, identity.configuration_hash),
                attack_id=case.id,
                target_id=identity.id,
                outcome=CompromiseOutcome.ERROR,
                objective_violated=None,
                model_compromise=False,
                system_compromise=False,
                confidence=1.0,
                evidence=response.evidence,
                error_kind=response.error_kind,
            )

        judgment = self.judge.evaluate(case, response)
        outcome = outcome_from_judgment(judgment)
        transcript = EvidenceRecord(
            kind=EvidenceKind.TRANSCRIPT,
            source="campaign_engine",
            observed_at="deterministic-test",
            content_hash=sha256((response.text or "").encode()).hexdigest(),
            data={"response_present": response.text is not None},
            redacted=True,
        )
        evidence = (*response.evidence, transcript)

        return ExecutionResult(
            execution_id=self._execution_id(case.id, identity.configuration_hash),
            attack_id=case.id,
            target_id=identity.id,
            outcome=outcome,
            objective_violated=judgment.objective_violated,
            model_compromise=judgment.model_compromise,
            system_compromise=judgment.system_compromise,
            confidence=judgment.confidence,
            evidence=evidence,
        )

    async def run(self, cases: tuple[AttackCase, ...]) -> tuple[ExecutionResult, ...]:
        results: list[ExecutionResult] = []
        for case in cases:
            results.append(await self.run_case(case))
        return tuple(results)

    @staticmethod
    def _execution_id(attack_id: str, target_hash: str) -> str:
        digest = sha256(f"{attack_id}:{target_hash}".encode()).hexdigest()[:16]
        return f"exec-{digest}"
