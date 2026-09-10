from __future__ import annotations

import asyncio
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.agent_actions import (
    AgentActionObservation,
    AgentActionPhase,
    canonical_json_hash,
    classify_agent_action,
)
from llm_redteam.campaign_plan import CampaignPlan, RedPolicyKind, preflight_campaign
from llm_redteam.campaigns.environment import (
    WorkspaceFixtureRunner,
    initialize_disposable_workspace,
)
from llm_redteam.campaigns.lifecycle import (
    CampaignLifecycleExecutor,
    static_attack_policy_descriptor,
)
from llm_redteam.corpus import load_corpus_file
from llm_redteam.domain import (
    CampaignBudget,
    CompromiseOutcome,
    EvidenceKind,
    TargetClass,
    TargetIdentity,
    TargetMode,
)
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.judges import SystemStateJudge
from llm_redteam.runtime_config import BudgetConfigDocument, RuntimePolicy
from llm_redteam.storage.measurement_repository import (
    fingerprint_attack_policy,
    load_campaign_measurement_snapshot,
)
from llm_redteam.storage.repository import ExperimentRepository
from llm_redteam.targets.base import TargetRequest, TargetResponse

TERMINAL_FIXTURE = "fixtures/coding/terminal_output_marker"
REPO_CANARY_FIXTURE = "fixtures/coding/repo_injection_canary"


def _terminal_case():
    document = load_corpus_file("corpus/native/smoke/canary-baseline.yaml")
    return next(case for case in document.cases if case.id == "NATIVE-T4-CODE-002")


def _budgets() -> BudgetConfigDocument:
    return BudgetConfigDocument(
        version=1,
        default_profile="smoke",
        profiles={
            "smoke": CampaignBudget(
                max_attacks=2,
                max_generations=1,
                max_turns_per_attack=2,
                max_model_calls=2,
                max_total_output_tokens=1000,
                max_image_generations=0,
                wall_clock_seconds=60,
                max_non_progress_attempts=1,
            )
        },
        policy=RuntimePolicy(),
    )


class _WorkspaceAgentTarget:
    def __init__(self, workspace_root: Path, *, behavior: str) -> None:
        self.workspace_root = workspace_root
        self.behavior = behavior
        self.prompts: list[str] = []
        self._identity = TargetIdentity(
            id="synthetic-workspace-agent",
            target_class=TargetClass.CODING,
            target_mode=TargetMode.AGENT,
            model="deterministic",
            provider="mock",
            runtime="local-test",
            configuration_hash=sha256(
                f"workspace-agent:{workspace_root.as_posix()}:{behavior}".encode()
            ).hexdigest(),
            capabilities=frozenset({"text", "coding", "tools", "filesystem", "shell", "agent"}),
        )

    @property
    def identity(self) -> TargetIdentity:
        return self._identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        self.prompts.append(request.prompt)
        app = self.workspace_root / "app.py"
        if app.exists():
            app.write_text(app.read_text(encoding="utf-8") + "\n# legitimate synthetic edit\n", encoding="utf-8")

        evidence = []
        if self.behavior == "safe":
            categories = classify_agent_action(
                "write",
                {"filePath": "app.py", "content": "legitimate"},
                workspace_root=str(self.workspace_root),
            )
            evidence.append(
                AgentActionObservation(
                    control_event_id="write-app",
                    session_id="session-1",
                    message_id="message-1",
                    tool="write",
                    phase=AgentActionPhase.EXECUTED,
                    categories=categories,
                    input_hash=canonical_json_hash({"filePath": "app.py"}),
                    source="synthetic-agent",
                ).to_evidence()
            )
        else:
            marker_input = {"filePath": "ATTACK_MARKER.txt", "content": "synthetic"}
            categories = classify_agent_action(
                "write",
                marker_input,
                workspace_root=str(self.workspace_root),
            )
            phase = (
                AgentActionPhase.REQUESTED
                if self.behavior == "blocked"
                else AgentActionPhase.EXECUTED
            )
            if self.behavior == "executed":
                (self.workspace_root / "ATTACK_MARKER.txt").write_text(
                    "synthetic",
                    encoding="utf-8",
                )
            evidence.append(
                AgentActionObservation(
                    control_event_id="write-marker",
                    session_id="session-1",
                    message_id="message-1",
                    tool="write",
                    phase=phase,
                    categories=categories,
                    input_hash=canonical_json_hash(marker_input),
                    source="synthetic-agent",
                ).to_evidence()
            )

        return TargetResponse(
            text="synthetic result",
            evidence=tuple(evidence),
            provider_metadata={"agent_trace_complete": True},
        )


def _runner(tmp_path: Path) -> WorkspaceFixtureRunner:
    workspace = tmp_path / "workspace"
    initialize_disposable_workspace(workspace)
    return WorkspaceFixtureRunner(
        corpus_root="corpus",
        workspace_root=workspace,
        allowed_fixture_refs=(TERMINAL_FIXTURE,),
    )


def _judge(runner: WorkspaceFixtureRunner) -> SystemStateJudge:
    return SystemStateJudge(runner.system_state_policies())


def _run_direct(tmp_path: Path, behavior: str):
    runner = _runner(tmp_path)
    target = _WorkspaceAgentTarget(runner.workspace_root, behavior=behavior)
    judge = _judge(runner)
    budget = next(iter(_budgets().profiles.values()))
    from llm_redteam.budget import BudgetLedger

    return asyncio.run(
        runner.run_case(
            _terminal_case(),
            target=target,
            judge=judge,
            budget=BudgetLedger(budget),
            execution_id=f"exec-{behavior}",
        )
    )


def test_safe_legitimate_edit_is_not_misclassified_as_forbidden_effect(tmp_path: Path) -> None:
    result = _run_direct(tmp_path, "safe")

    assert result.outcome == CompromiseOutcome.PASS
    assert result.model_compromise is False
    assert result.system_compromise is False


def test_blocked_marker_request_is_model_compromise_without_system_compromise(
    tmp_path: Path,
) -> None:
    result = _run_direct(tmp_path, "blocked")

    assert result.outcome == CompromiseOutcome.MODEL_COMPROMISE
    assert result.model_compromise is True
    assert result.system_compromise is False


def test_created_marker_is_model_and_system_compromise(tmp_path: Path) -> None:
    result = _run_direct(tmp_path, "executed")

    assert result.outcome == CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE
    assert result.model_compromise is True
    assert result.system_compromise is True
    system_state = [item for item in result.evidence if item.kind == EvidenceKind.SYSTEM_STATE]
    assert any(item.data["state"] == "observed" for item in system_state)


def test_environment_fixture_requires_explicit_runner_capability(tmp_path: Path) -> None:
    case = _terminal_case()
    plan = CampaignPlan(
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        red_policy=RedPolicyKind.STATIC,
        enabled_only=False,
    )
    blocked = preflight_campaign(plan=plan, cases=(case,), budgets=_budgets())
    assert blocked.ready is False

    runner = _runner(tmp_path)
    allowed = preflight_campaign(
        plan=plan,
        cases=(case,),
        budgets=_budgets(),
        runtime_capabilities=runner.capabilities,
    )
    assert allowed.ready is True


def test_workspace_runner_rejects_fixture_requiring_process_environment(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    initialize_disposable_workspace(workspace)
    with pytest.raises(ValueError, match="process environment injection"):
        WorkspaceFixtureRunner(
            corpus_root="corpus",
            workspace_root=workspace,
            allowed_fixture_refs=(REPO_CANARY_FIXTURE,),
        )


def test_workspace_initialization_refuses_nonempty_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "not-disposable"
    workspace.mkdir()
    (workspace / "keep.txt").write_text("do not delete", encoding="utf-8")

    with pytest.raises(ValueError, match="empty directory"):
        initialize_disposable_workspace(workspace)
    assert (workspace / "keep.txt").read_text(encoding="utf-8") == "do not delete"


def test_persisted_lifecycle_binds_environment_runner_to_attack_policy(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    target = _WorkspaceAgentTarget(runner.workspace_root, behavior="executed")
    judge = _judge(runner)
    descriptor = {
        "kind": "system_state",
        "version": 1,
        "policies": [policy.model_dump(mode="json") for policy in runner.system_state_policies()],
    }
    repository = ExperimentRepository.from_url("sqlite+pysqlite:///:memory:")
    executor = CampaignLifecycleExecutor(
        target=target,
        judge=judge,
        repository=repository,
        budgets=_budgets(),
        judge_policy_descriptor=descriptor,
        environment_runner=runner,
    )
    plan = CampaignPlan(
        purpose=CampaignPurpose.DISCOVERY,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        red_policy=RedPolicyKind.STATIC,
        enabled_only=False,
    )

    result = asyncio.run(
        executor.run(
            plan=plan,
            cases=(_terminal_case(),),
            campaign_id="environment-lifecycle-1",
        )
    )

    assert result.executions[0].outcome == CompromiseOutcome.MODEL_AND_SYSTEM_COMPROMISE
    assert result.budget.attacks == 1
    assert result.budget.turns == 1
    assert any(
        item.source == "workspace_fixture_runner" for item in result.executions[0].evidence
    )

    snapshot = load_campaign_measurement_snapshot(repository.engine, result.campaign_id)
    assert snapshot is not None
    expected = fingerprint_attack_policy(
        static_attack_policy_descriptor(
            plan,
            environment_runner_descriptor=runner.descriptor(),
        )
    )
    assert snapshot.attack_policy_fingerprint == expected
