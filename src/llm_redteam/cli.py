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
from .campaigns.lifecycle import deterministic_judge_policy_descriptor
from .corpus import load_corpus_files
from .domain import TargetClass, TargetMode
from .evaluation_protocol import CampaignPurpose
from .hal_smoke_operator import (
    build_hal_smoke_live_runner,
    capture_hal_smoke_runtime,
    rebuild_captured_staged_store,
    verify_hal_smoke_runtime_images,
)
from .hal_smoke_preflight import (
    build_hal_smoke_static_plan,
    compose_hal_smoke_offline,
    load_hal_smoke_runtime_pins,
)
from .hal_smoke_scenario import (
    build_hal_smoke_campaign_plan,
    build_hal_smoke_case,
)
from .judges.deterministic import DeterministicJudge
from .model_client import OpenAICompatibleRoleModelClient
from .model_inventory import (
    load_openwebui_ollama_inventory,
    validate_local_only_model_selection,
)
from .model_roles import ModelRole, load_models_config
from .reference_artifact_provenance import build_reference_execution_provenance
from .reference_artifact_qualification import (
    load_ollama_artifact_contracts,
    load_ollama_tags_snapshot,
    qualify_admitted_ollama_artifacts,
)
from .reference_evaluation import (
    ReferenceEvaluationStage,
    load_reference_evaluation_spec,
)
from .reference_runner import ReferenceEvaluationRunResult, run_reference_evaluation_stage
from .runtime_config import load_budget_config
from .storage.execution_provenance_repository import ExecutionProvenanceDescriptor
from .storage.repository import ExperimentRepository
from .targets.base import SessionMode
from .targets.openai_compatible import OpenAICompatibleConfig, OpenAICompatibleTarget

DEFAULT_BUDGET_CONFIG = Path("config/budgets.yaml")
DEFAULT_REFERENCE_SPEC = Path("config/reference-evaluation-v1.yaml")
DEFAULT_REFERENCE_DISCOVERY_CORPUS = Path("corpus/native/multiturn/reference-discovery-v1.yaml")
DEFAULT_REFERENCE_EVALUATION_CORPUS = Path("corpus/native/multiturn/synthetic-sequences-v1.yaml")
DEFAULT_REFERENCE_BLUE_POLICY = Path("config/reference-blue-policy-v1.txt")
DEFAULT_REFERENCE_DATABASE_URL = "sqlite+pysqlite:///reference-evaluation.db"
DEFAULT_HAL_SMOKE_MODELS = Path("config/models.hal-smoke.example.yaml")
DEFAULT_HAL_SMOKE_BLUE_MODEL = "ornith-1.5:9b"
DEFAULT_OLLAMA_MODELS_ROOT = Path.home() / ".ollama" / "models"
REFERENCE_CANARY = "RT_SYNTHETIC_CANARY"

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


@app.command("hal-smoke-preflight")
def hal_smoke_preflight_command(
    models_config: Annotated[
        Path,
        typer.Option("--models", help="Bounded local HAL smoke model configuration."),
    ] = DEFAULT_HAL_SMOKE_MODELS,
    blue_model: Annotated[
        str,
        typer.Option("--blue-model", help="Blue Ollama model for the isolated AGENT peer."),
    ] = DEFAULT_HAL_SMOKE_BLUE_MODEL,
    model_inventory: Annotated[
        Path | None,
        typer.Option("--model-inventory", help="Saved fresh OpenWebUI /api/models response."),
    ] = None,
    artifact_contracts: Annotated[
        Path | None,
        typer.Option("--artifact-contracts", help="Exact Ollama artifact contracts."),
    ] = None,
    ollama_tags_snapshot: Annotated[
        Path | None,
        typer.Option("--ollama-tags-snapshot", help="Saved fresh local Ollama /api/tags."),
    ] = None,
    runtime_pins: Annotated[
        Path | None,
        typer.Option("--runtime-pins", help="Digest-pinned HAL/OpenCode runtime inputs."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Build a zero-inference HAL AGENT smoke plan or full offline composition.

    With no HAL evidence arguments, this validates only the bounded static model policy.
    Supplying any runtime evidence option requires all four evidence documents. Even a
    successful full offline composition is not live runtime admission.
    """

    try:
        models = load_models_config(models_config)
        static_plan = build_hal_smoke_static_plan(
            models=models,
            blue_model_id=blue_model,
        )
        evidence_paths = (
            model_inventory,
            artifact_contracts,
            ollama_tags_snapshot,
            runtime_pins,
        )
        supplied = sum(path is not None for path in evidence_paths)
        if supplied not in {0, len(evidence_paths)}:
            raise ValueError(
                "HAL offline composition requires all of --model-inventory, "
                "--artifact-contracts, --ollama-tags-snapshot and --runtime-pins"
            )

        composition = None
        if supplied:
            assert model_inventory is not None
            assert artifact_contracts is not None
            assert ollama_tags_snapshot is not None
            assert runtime_pins is not None
            pins = load_hal_smoke_runtime_pins(runtime_pins)
            inventory = load_openwebui_ollama_inventory(model_inventory)
            blue_peer_endpoint = (
                f"http://{pins.model_endpoint_host}:{pins.model_endpoint_port}"
            )
            admission = validate_local_only_model_selection(
                models=models,
                inventory=inventory,
                blue_model_id=static_plan.blue_model_id,
                blue_endpoint=blue_peer_endpoint,
                blue_required_capabilities={"text"},
                allowed_endpoint_hosts={pins.model_endpoint_host},
            )
            qualification = qualify_admitted_ollama_artifacts(
                admission=admission,
                inventory=inventory,
                contracts=load_ollama_artifact_contracts(artifact_contracts),
                tags_snapshot=load_ollama_tags_snapshot(ollama_tags_snapshot),
            )
            composition = compose_hal_smoke_offline(
                static_plan=static_plan,
                admission=admission,
                qualification=qualification,
                pins=pins,
            )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    payload = _hal_smoke_preflight_payload(static_plan, composition)
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_hal_smoke_preflight(payload)


@app.command("hal-smoke-capture-runtime")
def hal_smoke_capture_runtime_command(
    artifact_contracts: Annotated[
        Path,
        typer.Option("--artifact-contracts", help="Exact local Ollama artifact contracts."),
    ],
    blue_model: Annotated[
        str,
        typer.Option("--blue-model", help="Blue model to stage and pin."),
    ] = DEFAULT_HAL_SMOKE_BLUE_MODEL,
    manifest_relative_path: Annotated[
        str,
        typer.Option("--blue-manifest-relative-path"),
    ] = "",
    source_models_root: Annotated[
        Path,
        typer.Option("--ollama-source-models-root"),
    ] = DEFAULT_OLLAMA_MODELS_ROOT,
    staging_root: Annotated[
        Path,
        typer.Option("--ollama-staging-root"),
    ] = Path(".llm-redteam-hal") / "ollama-staging",
    opencode_application_version: Annotated[
        str,
        typer.Option("--opencode-application-version"),
    ] = "",
    opencode_image_ref: Annotated[
        str,
        typer.Option("--opencode-image-ref"),
    ] = "",
    ollama_peer_image_ref: Annotated[
        str,
        typer.Option("--ollama-peer-image-ref"),
    ] = "",
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write captured runtime pins as JSON."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Capture exact HAL runtime pins without model inference."""

    try:
        contracts = load_ollama_artifact_contracts(artifact_contracts)
        blue_contract = _require_ollama_contract(contracts, blue_model)
        captured = capture_hal_smoke_runtime(
            blue_artifact_contract=blue_contract,
            manifest_relative_path=manifest_relative_path,
            source_models_root=source_models_root,
            staging_root=staging_root,
            opencode_application_version=opencode_application_version,
            opencode_image_ref=opencode_image_ref,
            ollama_peer_image_ref=ollama_peer_image_ref,
        )
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                captured.runtime_pins.model_dump_json(indent=2) + "\n",
                encoding="utf-8",
            )
    except (OSError, RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    payload = {
        "runtime_pins_sha256": captured.runtime_pins.pins_sha256,
        "staged_blue_store_identity_sha256": (
            captured.staged_store.identity.identity_sha256
        ),
        "opencode_image_id": captured.opencode_image.image_id,
        "ollama_peer_image_id": captured.ollama_peer_image.image_id,
        "output": str(output) if output is not None else None,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        table = Table(title="HAL runtime capture")
        for key, value in payload.items():
            table.add_row(key, str(value))
        console.print(table)


@app.command("hal-smoke-run")
def hal_smoke_run_command(
    models_config: Annotated[Path, typer.Option("--models")] = DEFAULT_HAL_SMOKE_MODELS,
    model_inventory: Annotated[Path, typer.Option("--model-inventory")] = ...,
    artifact_contracts: Annotated[Path, typer.Option("--artifact-contracts")] = ...,
    ollama_tags_snapshot: Annotated[Path, typer.Option("--ollama-tags-snapshot")] = ...,
    runtime_pins: Annotated[Path, typer.Option("--runtime-pins")] = ...,
    blue_model: Annotated[str, typer.Option("--blue-model")] = DEFAULT_HAL_SMOKE_BLUE_MODEL,
    manifest_relative_path: Annotated[
        str,
        typer.Option("--blue-manifest-relative-path"),
    ] = "",
    source_models_root: Annotated[
        Path,
        typer.Option("--ollama-source-models-root"),
    ] = DEFAULT_OLLAMA_MODELS_ROOT,
    staging_root: Annotated[
        Path,
        typer.Option("--ollama-staging-root"),
    ] = Path(".llm-redteam-hal") / "ollama-staging",
    workspace_template_root: Annotated[
        Path,
        typer.Option("--workspace-template-root"),
    ] = Path("."),
    workspace_sandbox_root: Annotated[
        Path,
        typer.Option("--workspace-sandbox-root"),
    ] = Path(".llm-redteam-hal") / "workspaces",
    budget_config: Annotated[Path, typer.Option("--budgets")] = DEFAULT_BUDGET_CONFIG,
    database_url: Annotated[
        str,
        typer.Option("--database-url"),
    ] = "sqlite+pysqlite:///hal-smoke.db",
    network_name: Annotated[
        str,
        typer.Option("--network-name"),
    ] = "llmrt-hal-smoke",
    campaign_id: Annotated[str | None, typer.Option("--campaign-id")] = None,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Explicitly cross the HAL runtime/inference boundary."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate or explicitly execute the fixed first HAL OpenCode smoke."""

    try:
        models = load_models_config(models_config)
        static_plan = build_hal_smoke_static_plan(
            models=models,
            blue_model_id=blue_model,
        )
        inventory = load_openwebui_ollama_inventory(model_inventory)
        pins = load_hal_smoke_runtime_pins(runtime_pins)
        admission = validate_local_only_model_selection(
            models=models,
            inventory=inventory,
            blue_model_id=blue_model,
            blue_endpoint=f"http://{pins.model_endpoint_host}:{pins.model_endpoint_port}",
            blue_required_capabilities={"text"},
            allowed_endpoint_hosts={pins.model_endpoint_host},
        )
        contracts = load_ollama_artifact_contracts(artifact_contracts)
        tags = load_ollama_tags_snapshot(ollama_tags_snapshot)
        qualification = qualify_admitted_ollama_artifacts(
            admission=admission,
            inventory=inventory,
            contracts=contracts,
            tags_snapshot=tags,
        )
        composition = compose_hal_smoke_offline(
            static_plan=static_plan,
            admission=admission,
            qualification=qualification,
            pins=pins,
        )
        blue_contract = _require_ollama_contract(contracts, blue_model)
        budgets = load_budget_config(budget_config)
        plan = build_hal_smoke_campaign_plan()
        case = build_hal_smoke_case()
    except (OSError, RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    if not execute:
        payload = {
            "phase": "validated_not_executed",
            "execute_required": True,
            "composition_sha256": composition.composition_sha256,
            "red_measurement_binding_sha256": composition.red_measurement_binding_sha256,
            "target_measurement_binding_sha256": (
                composition.target_measurement_binding_sha256
            ),
            "runtime_pins_sha256": pins.pins_sha256,
            "blue_model": blue_model,
            "case_id": case.id,
            "budget_profile": plan.budget_profile,
            "local_paths": {
                "source_models_root": str(source_models_root),
                "staging_root": str(staging_root),
                "workspace_template_root": str(workspace_template_root),
                "workspace_sandbox_root": str(workspace_sandbox_root),
            },
        }
        if json_output:
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        else:
            table = Table(title="HAL smoke validated (not executed)")
            table.add_row("Composition", composition.composition_sha256)
            table.add_row("Blue model", blue_model)
            table.add_row("Case", case.id)
            table.add_row("Runtime boundary", "NOT CROSSED; rerun with --execute on HAL")
            console.print(table)
        return

    try:
        verify_hal_smoke_runtime_images(runtime_pins=pins)
        staged_store = rebuild_captured_staged_store(
            runtime_pins=pins,
            blue_artifact_contract=blue_contract,
            manifest_relative_path=manifest_relative_path,
            source_models_root=source_models_root,
            staging_root=staging_root,
        )
        live_runner = build_hal_smoke_live_runner(
            composition=composition,
            admission=admission,
            qualification=qualification,
            models=models,
            staged_store=staged_store,
            blue_artifact_contract=blue_contract,
            workspace_template_root=workspace_template_root,
            workspace_sandbox_root=workspace_sandbox_root,
            repository=ExperimentRepository.from_url(database_url),
            budgets=budgets,
            network_name=network_name,
        )
        result = asyncio.run(
            _run_hal_smoke_live_and_close(
                live_runner,
                plan=plan,
                case=case,
                campaign_id=campaign_id,
            )
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    payload = {
        "phase": "executed",
        "campaign_id": result.campaign.campaign_id,
        "campaign_status": result.campaign.status.value,
        "measurement_hash": result.campaign.measurement_hash,
        "blue_infrastructure_proof_sha256": result.blue_infrastructure.proof_sha256,
        "blue_teardown_proof_sha256": result.blue_release.teardown_proof_sha256,
        "red_runtime_recheck_proof_sha256": result.red_runtime_recheck.proof_sha256,
        "execution_provenance_hashes": dict(result.execution_provenance_hashes),
        "isolation_record_count": len(result.campaign.isolation_records),
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        table = Table(title="HAL smoke execution")
        table.add_row("Campaign", result.campaign.campaign_id)
        table.add_row("Status", result.campaign.status.value)
        table.add_row("Measurement", result.campaign.measurement_hash)
        table.add_row("Isolation records", str(len(result.campaign.isolation_records)))
        console.print(table)


@app.command("reference-run")
def reference_run(
    models_config: Annotated[
        Path,
        typer.Option("--models", help="Concrete local Red role model configuration."),
    ],
    model_inventory: Annotated[
        Path,
        typer.Option(
            "--model-inventory",
            help=(
                "Saved OpenWebUI /api/models response used to prove every enabled role "
                "and the Blue target are truly local before inference."
            ),
        ),
    ],
    target_model: Annotated[
        str,
        typer.Option("--target-model", help="Concrete Blue model exposed by the target."),
    ],
    stage: Annotated[
        ReferenceEvaluationStage,
        typer.Option("--stage"),
    ] = ReferenceEvaluationStage.INSTRUMENTATION_SMOKE,
    artifact_contracts: Annotated[
        Path | None,
        typer.Option(
            "--artifact-contracts",
            help=(
                "Frozen exact Ollama artifact contracts. Required with --ollama-tags-snapshot "
                "for POLICY_QUALIFICATION."
            ),
        ),
    ] = None,
    ollama_tags_snapshot: Annotated[
        Path | None,
        typer.Option(
            "--ollama-tags-snapshot",
            help=(
                "Saved local Ollama /api/tags response. Required with --artifact-contracts "
                "for POLICY_QUALIFICATION."
            ),
        ),
    ] = None,
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

    The default stage is the bounded instrumentation smoke. A fresh saved model inventory
    is mandatory and must prove Red and Blue are not remote Ollama proxies before any
    model client is constructed. ``POLICY_QUALIFICATION`` additionally requires a frozen
    artifact-contract document plus a saved local Ollama ``/api/tags`` snapshot; exact
    artifact verification is completed before any target or Red client is constructed.
    The resulting provenance is hash-bound into both paired campaigns before inference.
    This command never enables agent network access, git push, real secrets, production
    targets, or cloud fallback.
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
        inventory = load_openwebui_ollama_inventory(model_inventory)
        admission_report = validate_local_only_model_selection(
            models=models,
            inventory=inventory,
            blue_model_id=target_model,
            blue_endpoint=target_base_url,
            blue_required_capabilities={"text"},
        )
        if (artifact_contracts is None) != (ollama_tags_snapshot is None):
            raise ValueError(
                "--artifact-contracts and --ollama-tags-snapshot must be provided together"
            )
        artifact_qualification = None
        if artifact_contracts is not None and ollama_tags_snapshot is not None:
            artifact_qualification = qualify_admitted_ollama_artifacts(
                admission=admission_report,
                inventory=inventory,
                contracts=load_ollama_artifact_contracts(artifact_contracts),
                tags_snapshot=load_ollama_tags_snapshot(ollama_tags_snapshot),
            )
        execution_provenance = build_reference_execution_provenance(
            stage=stage,
            admission=admission_report,
            artifact_qualification=artifact_qualification,
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
                execution_provenance=execution_provenance,
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
    execution_provenance: tuple[ExecutionProvenanceDescriptor, ...],
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
            execution_provenance=execution_provenance,
        )
    finally:
        await red_client.aclose()
        await target.aclose()


def _hal_smoke_preflight_payload(static_plan, composition) -> dict[str, object]:
    payload: dict[str, object] = {
        "phase": "static" if composition is None else "offline_composed",
        "static_plan_sha256": static_plan.plan_sha256,
        "static_plan": static_plan.model_dump(mode="json"),
        "live_runtime_admitted": False,
    }
    if composition is None:
        payload["required_offline_inputs"] = [
            "fresh OpenWebUI /api/models",
            "exact Ollama artifact contracts",
            "fresh local Ollama /api/tags",
            "digest-pinned HAL runtime pins",
        ]
        return payload
    payload.update(
        {
            "composition_sha256": composition.composition_sha256,
            "red_measurement_binding_sha256": (
                composition.red_measurement_binding_sha256
            ),
            "blue_artifact_digest": composition.blue_artifact_digest,
            "model_network_profile_sha256": composition.model_network.profile_sha256,
            "model_peer_profile_sha256": composition.model_peer.profile_sha256,
            "opencode_launch_policy_sha256": (
                composition.opencode_launch_policy.policy_sha256
            ),
            "opencode_agent_profile_sha256": composition.opencode_agent.profile_sha256,
            "sandbox_policy_sha256": composition.sandbox_policy.policy_sha256,
            "live_evidence_requirements": list(composition.live_evidence_requirements),
        }
    )
    return payload


def _print_hal_smoke_preflight(payload: dict[str, object]) -> None:
    table = Table(title="HAL smoke preflight")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Phase", str(payload["phase"]))
    table.add_row("Static plan", str(payload["static_plan_sha256"]))
    table.add_row("Live runtime admitted", str(payload["live_runtime_admitted"]))
    if payload["phase"] == "offline_composed":
        table.add_row("Composition", str(payload["composition_sha256"]))
        table.add_row(
            "Red measurement binding",
            str(payload["red_measurement_binding_sha256"]),
        )
        table.add_row("Blue artifact", str(payload["blue_artifact_digest"]))
        table.add_row(
            "Outstanding live evidence",
            str(len(payload["live_evidence_requirements"])),
        )
    else:
        table.add_row(
            "Required offline inputs",
            str(len(payload["required_offline_inputs"])),
        )
    console.print(table)



def _require_ollama_contract(contracts, model_id: str):
    matches = [contract for contract in contracts.contracts if contract.model_id == model_id]
    if len(matches) != 1:
        raise ValueError(
            f"artifact contracts must contain exactly one contract for Blue model: {model_id}"
        )
    return matches[0]


async def _run_hal_smoke_live_and_close(live_runner, *, plan, case, campaign_id):
    try:
        return await live_runner.run(
            plan=plan,
            cases=(case,),
            campaign_id=campaign_id,
        )
    finally:
        for client in (live_runner.red_model_client, live_runner.red_tags_probe):
            close = getattr(client, "aclose", None)
            if close is not None:
                await close()


def _reference_result_payload(result: ReferenceEvaluationRunResult) -> dict[str, object]:
    baseline = result.report.baseline.campaign
    treatment = result.report.treatment.campaign
    qualification = result.qualification
    return {
        "stage": result.stage.value,
        "experiment_id": result.report.contract.experiment_id,
        "target_snapshot_id": result.report.contract.target_snapshot_id,
        "evaluation_manifest_hash": result.manifest.content_hash,
        "execution_provenance": dict(result.execution_provenance_hashes),
        "pair_count": result.report.pair_count,
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
    provenance = payload["execution_provenance"]
    assert isinstance(provenance, dict)
    table.add_row(
        "Execution provenance",
        ", ".join(f"{kind}={digest}" for kind, digest in provenance.items()) or "none",
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