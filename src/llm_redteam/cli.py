"""Minimal operator CLI for validation and fail-closed campaign planning."""

from __future__ import annotations

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
from .corpus import load_corpus_files
from .domain import TargetClass, TargetMode
from .evaluation_protocol import CampaignPurpose
from .model_roles import load_models_config
from .runtime_config import load_budget_config
from .targets.base import SessionMode

DEFAULT_BUDGET_CONFIG = Path("config/budgets.yaml")

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
