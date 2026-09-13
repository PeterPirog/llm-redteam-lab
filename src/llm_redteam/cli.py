"""Operator CLI for validation, fail-closed planning and reference evaluation."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .campaign_plan import (
    CampaignPlan,
    CampaignPreflight,
    PreflightSeverity,
    RedPolicyKind,
    load_evaluation_manifest,
    preflight_campaign,
)
from .campaigns.lifecycle import METRIC_DEFINITION_VERSION, deterministic_judge_policy_descriptor
from .corpus import load_corpus_files
from .domain import TargetClass, TargetMode
from .evaluation_protocol import CampaignPurpose
from .inference_contract import InferenceScope
from .judges.deterministic import DeterministicJudge
from .model_client import OpenAICompatibleRoleModelClient
from .model_roles import ModelRole, load_models_config
from .reference_evaluation import (
    ReferenceEvaluationStage,
    load_reference_evaluation_spec,
)
from .reference_runner import ReferenceEvaluationRunResult, run_reference_evaluation_stage
from .runtime_config import load_budget_config
from .storage.repository import ExperimentRepository
from .targets.base import SessionMode
from .targets.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleTarget

DEFAULT_BUDGET_CONFIG = Path("config/budgets.yaml")
DEFAULT_REFERENCE_SPEC = Path("config/reference-evaluation-v1.yaml")
DEFAULT_REFERENCE_DISCOVERY_CORPUS = Path("corpus/native/multiturn/reference-discovery-v1.yaml")
DEFAULT_REFERENCE_EVALUATION_CORPUS = Path("corpus/native/multiturn/synthetic-sequences-v1.yaml")
DEFAULT_REFERENCE_BLUE_POLICY = Path("config/reference-blue-policy-v1.txt")
DEFAULT_REFERENCE_DATABASE_URL = "sqlite+pysqlite:///reference-evaluation.db"
REFERENCE_CANARY = "RT_SYNTHETIC_CANARY"
_REFERENCE_FIXED_CORPUS_INTERPRETATION = (
    "Rates and paired effects describe the exact held-out evaluation manifest under the "
    "recorded target, Red policy, Judge and budget conditions. They do not by themselves "
    "estimate vulnerability over a broader population of possible attacks."
)

app = typer.Typer(
    name="llm-redteam",
    no_args_is_help=True,
    help="Authorized, evidence-driven AI red-team laboratory.",
)
console = Console()


@app.command("validate-corpus")
def validate_corpus(
    paths: Annotated[
        list[Path],
        typer.Argument(help="One or more normalized corpus YAML files."),
    ],
) -> None:
    """Validate corpus documents without target or model inference."""

    cases = load_corpus_files(paths)
    console.print(
        f"[green]VALID[/green] {len(cases)} attack cases across {len(paths)} file(s)"
    )


@app.command("plan")
def plan_campaign(
    corpus: Annotated[
        list[Path],
        typer.Option("--corpus", "-c", help="Corpus YAML file."),
    ],
    target_class: Annotated[TargetClass, typer.Option("--target-class")],
    target_mode: Annotated[TargetMode, typer.Option("--target-mode")],
    purpose: Annotated[
        CampaignPurpose,
        typer.Option("--purpose"),
    ] = CampaignPurpose.DISCOVERY,
    budget_config: Annotated[
        Path,
        typer.Option("--budgets"),
    ] = DEFAULT_BUDGET_CONFIG,
    budget_profile: Annotated[str | None, typer.Option("--budget-profile")] = None,
    models_config: Annotated[Path | None, typer.Option("--models")] = None,
    evaluation_manifest: Annotated[
        Path | None,
        typer.Option("--evaluation-manifest"),
    ] = None,
    red_policy: Annotated[
        RedPolicyKind,
        typer.Option("--red-policy"),
    ] = RedPolicyKind.STATIC,
    replicates: Annotated[int, typer.Option("--replicates", min=1)] = 1,
    session_mode: Annotated[
        SessionMode,
        typer.Option("--session-mode"),
    ] = SessionMode.REPLAY,
    target_snapshot_id: Annotated[str | None, typer.Option("--target-snapshot-id")] = None,
    attack_policy_fingerprint: Annotated[
        str | None,
        typer.Option("--attack-policy-fingerprint"),
    ] = None,
    judge_policy_fingerprint: Annotated[
        str | None,
        typer.Option("--judge-policy-fingerprint"),
    ] = None,
    include_disabled: Annotated[bool, typer.Option("--include-disabled")] = False,
    allow_agent_network: Annotated[bool, typer.Option("--allow-agent-network")] = False,
    allow_agent_git_push: Annotated[
        bool,
        typer.Option("--allow-agent-git-push"),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Build a campaign plan and stop before any target/model call."""

    cases = load_corpus_files(corpus)
    budgets = load_budget_config(budget_config)
    models = load_models_config(models_config) if models_config is not None else None
    manifest = (
        load_evaluation_manifest(evaluation_manifest)
        if evaluation_manifest is not None
        else None
    )
    plan = CampaignPlan(
        purpose=purpose,
        target_class=target_class,
        target_mode=target_mode,
        budget_profile=budget_profile,
        red_policy=red_policy,
        replicates=replicates,
        enabled_only=not include_disabled,
        session_mode=session_mode,
        target_snapshot_id=target_snapshot_id,
        attack_policy_fingerprint=attack_policy_fingerprint,
        judge_policy_fingerprint=judge_policy_fingerprint,
        allow_agent_network=allow_agent_network,
        allow_agent_git_push=allow_agent_git_push,
    )
    report = preflight_campaign(
        plan=plan,
        cases=cases,
        budgets=budgets,
        models=models,
        evaluation_manifest=manifest,
    )

    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        _print_preflight(report)
    if not report.ready:
        raise typer.Exit(code=2)


@app.command("reference-run")
def reference_run(
    models_config: Annotated[
        Path,
        typer.Option("--models", help="Concrete local Red role model configuration."),
    ],
    target_model: Annotated[
        str,
        typer.Option("--target-model", help="Concrete Blue model exposed by the target."),
    ],
    stage: Annotated[
        ReferenceEvaluationStage,
        typer.Option("--stage"),
    ] = ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
    target_base_url: Annotated[
        str,
        typer.Option("--target-base-url"),
    ] = "http://localhost:11434",
    target_id: Annotated[str, typer.Option("--target-id")] = "reference-local-model",
    target_endpoint_path: Annotated[
        str,
        typer.Option("--target-endpoint-path"),
    ] = "/v1/chat/completions",
    target_system_prompt_file: Annotated[
        Path,
        typer.Option("--target-system-prompt-file"),
    ] = DEFAULT_REFERENCE_BLUE_POLICY,
    spec_path: Annotated[Path, typer.Option("--spec")] = DEFAULT_REFERENCE_SPEC,
    discovery_corpus: Annotated[
        Path,
        typer.Option("--discovery-corpus"),
    ] = DEFAULT_REFERENCE_DISCOVERY_CORPUS,
    evaluation_corpus: Annotated[
        Path,
        typer.Option("--evaluation-corpus"),
    ] = DEFAULT_REFERENCE_EVALUATION_CORPUS,
    budget_config: Annotated[Path, typer.Option("--budgets")] = DEFAULT_BUDGET_CONFIG,
    database_url: Annotated[
        str,
        typer.Option("--database-url"),
    ] = DEFAULT_REFERENCE_DATABASE_URL,
    target_max_output_tokens: Annotated[
        int,
        typer.Option("--target-max-output-tokens", min=1),
    ] = 1024,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run the fixed-corpus local multi-turn reference experiment.

    The default stage is the bounded instrumentation smoke. Policy qualification
    requires explicitly selecting ``POLICY_QUALIFICATION``. This command never
    enables agent network access, git push, real secrets, or production targets.
    """

    try:
        spec = load_reference_evaluation_spec(spec_path)
        cases = load_corpus_files((discovery_corpus, evaluation_corpus))
        budgets = load_budget_config(budget_config)
        models = load_models_config(models_config)
        for role in (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR):
            role_config = models.role(role)
            if not role_config.endpoint:
                raise ValueError(f"reference Red role requires endpoint: {role.value}")
        system_prompt = target_system_prompt_file.read_text(encoding="utf-8").strip()
        if not system_prompt:
            raise ValueError("reference Blue system policy cannot be empty")
        if REFERENCE_CANARY not in system_prompt:
            raise ValueError(
                "reference Blue system policy must explicitly bind RT_SYNTHETIC_CANARY"
            )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(
            id=target_id,
            base_url=target_base_url,
            endpoint_path=target_endpoint_path,
            model=target_model,
            provider=spec.required_target_provider,
            target_class=spec.target_class,
            target_mode=spec.target_mode,
            temperature=0.0,
            max_output_tokens=target_max_output_tokens,
            system_prompt=system_prompt,
        )
    )
    red_client = OpenAICompatibleRoleModelClient(models)
    repository = ExperimentRepository.from_url(database_url)
    judge = DeterministicJudge(canary=REFERENCE_CANARY)

    try:
        result = asyncio.run(
            _execute_reference_run(
                stage=stage,
                spec=spec,
                cases=cases,
                budgets=budgets,
                models=models,
                target=target,
                judge=judge,
                red_client=red_client,
                repository=repository,
            )
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    payload = _reference_result_payload(result)
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_reference_result(payload)


async def _execute_reference_run(
    *,
    stage,
    spec,
    cases,
    budgets,
    models,
    target: OpenAICompatibleTarget,
    judge: DeterministicJudge,
    red_client: OpenAICompatibleRoleModelClient,
    repository: ExperimentRepository,
) -> ReferenceEvaluationRunResult:
    try:
        return await run_reference_evaluation_stage(
            stage=stage,
            spec=spec,
            cases=cases,
            budgets=budgets,
            models=models,
            target=target,
            judge=judge,
            judge_policy_descriptor=deterministic_judge_policy_descriptor(
                canary=REFERENCE_CANARY
            ),
            red_model_client=red_client,
            repository=repository,
        )
    finally:
        await red_client.aclose()
        await target.aclose()


def _reference_result_payload(result: ReferenceEvaluationRunResult) -> dict[str, object]:
    baseline = result.report.baseline.campaign
    treatment = result.report.treatment.campaign
    qualification = result.qualification
    return {
        "stage": result.stage.value,
        "experiment_id": result.report.contract.experiment_id,
        "target_snapshot_id": result.report.contract.target_snapshot_id,
        "evaluation_manifest_hash": result.manifest.content_hash,
        "pair_count": result.report.pair_count,
        "measurement_claim": {
            "inference_scope": InferenceScope.FIXED_CORPUS.value,
            "generalized_claim_supported": False,
            "metric_definition_version": METRIC_DEFINITION_VERSION,
            "statistical_unit": "case_replicate_pair",
            "interpretation": _REFERENCE_FIXED_CORPUS_INTERPRETATION,
        },
        "baseline": {
            "attack_success_rate": baseline.attack_success_rate.value,
            "model_compromise_rate": baseline.model_compromise_rate.value,
            "system_compromise_rate": baseline.system_compromise_rate.value,
        },
        "treatment": {
            "attack_success_rate": treatment.attack_success_rate.value,
            "model_compromise_rate": treatment.model_compromise_rate.value,
            "system_compromise_rate": treatment.system_compromise_rate.value,
        },
        "paired": {
            "objective_violation_rate_delta": result.report.objective_violation_rate_delta,
            "exact_mcnemar_p_value": result.report.exact_mcnemar_p_value,
            "discordant_pairs": result.report.discordant_pairs,
            "mean_target_interaction_delta": result.report.mean_target_interaction_delta,
            "mean_output_token_delta": result.report.mean_output_token_delta,
        },
        "qualification": (
            qualification.model_dump(mode="json") if qualification is not None else None
        ),
    }


def _print_reference_result(payload: dict[str, object]) -> None:
    table = Table(title="Reference evaluation")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Stage", str(payload["stage"]))
    table.add_row("Experiment", str(payload["experiment_id"]))
    table.add_row("Pairs", str(payload["pair_count"]))
    claim = payload["measurement_claim"]
    assert isinstance(claim, dict)
    table.add_row("Inference scope", str(claim["inference_scope"]))
    table.add_row(
        "Generalized claim",
        "supported" if claim["generalized_claim_supported"] else "not supported",
    )
    paired = payload["paired"]
    assert isinstance(paired, dict)
    table.add_row("Violation-rate delta", str(paired["objective_violation_rate_delta"]))
    table.add_row("Exact McNemar p", str(paired["exact_mcnemar_p_value"]))
    qualification = payload["qualification"]
    if isinstance(qualification, dict):
        table.add_row("Qualification", str(qualification["status"]))
    else:
        table.add_row("Qualification", "not issued by instrumentation smoke")
    console.print(table)


def _print_preflight(report: CampaignPreflight) -> None:
    table = Table(title="Campaign preflight")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Status", "READY" if report.ready else "BLOCKED")
    table.add_row("Purpose", report.purpose.value)
    table.add_row("Target", f"{report.target_class.value}/{report.target_mode.value}")
    table.add_row("Budget", report.budget_profile)
    table.add_row("Red policy", report.red_policy.value)
    table.add_row("Cases", str(len(report.selected_case_ids)))
    table.add_row("Planned trials", str(report.planned_trials))
    table.add_row("Multi-turn cases", str(report.multi_turn_cases))
    table.add_row("Image cases", str(report.image_cases))
    table.add_row("Model roles", ", ".join(report.required_model_roles) or "none")
    console.print(table)
    for issue in report.issues:
        style = "red" if issue.severity == PreflightSeverity.ERROR else "yellow"
        console.print(
            f"[{style}]{issue.severity.value}[/{style}] {issue.code}: {issue.message}"
        )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
