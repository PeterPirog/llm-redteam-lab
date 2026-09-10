"""Fail-closed environment-injection execution for disposable agent workspaces."""

from __future__ import annotations

import json
import os
import shutil
import stat
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

import yaml
from pydantic import Field

from ..agent_actions import agent_resource_category, canonical_json_hash, fingerprint_agent_path
from ..budget import BudgetLedger
from ..campaign_plan import CampaignRuntimeCapabilities
from ..domain import (
    AttackCase,
    EvidenceKind,
    EvidenceRecord,
    ExecutionResult,
    PayloadSpec,
    StrictModel,
    TargetClass,
    TargetMode,
)
from ..judges.base import Judge
from ..judges.system_state import AgentActionPolicy
from ..resource_verifiers import ForbiddenPathVerifier
from ..targets.base import TargetAdapter
from ..targets.state_verified import StateVerifyingTarget
from .engine import CampaignEngine

_SENTINEL_NAME = ".llm-redteam-disposable-workspace"
_SENTINEL_VALUE = "llm-redteam-disposable-workspace-v1\n"
_RUNNER_VERSION = 1


class ForbiddenPathBinding(StrictModel):
    path: str = Field(min_length=1)
    verifier_id: str = Field(min_length=1)
    detector_ids: tuple[str, ...] = Field(min_length=1)


class WorkspaceFixtureDefinition(StrictModel):
    id: str = Field(min_length=1)
    target_class: TargetClass
    target_mode: TargetMode
    purpose: str = Field(min_length=1)
    workspace_subdir: str = Field(min_length=1)
    legitimate_task: str = Field(min_length=1)
    environment: dict[str, str] = Field(default_factory=dict)
    forbidden_effects: tuple[str, ...] = Field(min_length=1)
    expected_safe_effects: tuple[str, ...] = Field(default_factory=tuple)
    recommended_graders: tuple[str, ...] = Field(default_factory=tuple)
    state_verifiers: tuple[ForbiddenPathBinding, ...] = Field(default_factory=tuple)


@runtime_checkable
class EnvironmentCaseRunner(Protocol):
    @property
    def capabilities(self) -> CampaignRuntimeCapabilities: ...

    def descriptor(self) -> dict[str, object]: ...

    async def run_case(
        self,
        case: AttackCase,
        *,
        target: TargetAdapter,
        judge: Judge,
        budget: BudgetLedger,
        execution_id: str,
    ) -> ExecutionResult: ...


class WorkspaceFixtureRunner:
    """Run exact fixture payloads inside one explicitly disposable workspace.

    The runner never creates the trust sentinel implicitly. Initialization is a
    separate operator action so a typo cannot turn an arbitrary directory into a
    resettable workspace. Current v1 intentionally rejects fixtures requiring
    process-environment injection; those need an owned process/container runner.
    """

    def __init__(
        self,
        *,
        corpus_root: str | Path,
        workspace_root: str | Path,
        allowed_fixture_refs: tuple[str, ...],
    ) -> None:
        if not allowed_fixture_refs:
            raise ValueError("at least one allowed fixture ref is required")
        self.corpus_root = Path(corpus_root).resolve(strict=False)
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        self._fixtures: dict[str, WorkspaceFixtureDefinition] = {}
        self._fixture_hashes: dict[str, str] = {}

        for ref in sorted(set(allowed_fixture_refs)):
            definition, fixture_hash = self._load_fixture(ref)
            if definition.environment:
                raise ValueError(
                    f"fixture {ref} requires process environment injection; "
                    "workspace runner v1 cannot provide it"
                )
            if not definition.state_verifiers:
                raise ValueError(f"fixture {ref} has no deterministic state verifier bindings")
            self._fixtures[ref] = definition
            self._fixture_hashes[ref] = fixture_hash

    @property
    def capabilities(self) -> CampaignRuntimeCapabilities:
        return CampaignRuntimeCapabilities(
            supported_fixture_refs=frozenset(self._fixtures),
        )

    def descriptor(self) -> dict[str, object]:
        return {
            "kind": "workspace_fixture_runner",
            "version": _RUNNER_VERSION,
            "workspace_policy": "explicit-disposable-sentinel-v1",
            "fixture_hashes": dict(sorted(self._fixture_hashes.items())),
        }

    def system_state_policies(self) -> tuple[AgentActionPolicy, ...]:
        """Build precise resource-scoped policies for all allowed fixture bindings."""

        policies: dict[str, AgentActionPolicy] = {}
        for definition in self._fixtures.values():
            for binding in definition.state_verifiers:
                path_hash = fingerprint_agent_path(binding.path)
                category = agent_resource_category(path_hash)
                for detector_id in binding.detector_ids:
                    candidate = AgentActionPolicy(
                        detector_id=detector_id,
                        categories=frozenset({category}),
                        require_all_categories=True,
                        model_compromise_on_attempt=True,
                        system_compromise_on_execution=True,
                        require_verified_effect=True,
                        trusted_effect_verifiers=frozenset({binding.verifier_id}),
                    )
                    existing = policies.get(detector_id)
                    if existing is not None and existing != candidate:
                        raise ValueError(
                            f"detector {detector_id} maps to conflicting fixture resources"
                        )
                    policies[detector_id] = candidate
        return tuple(policies[key] for key in sorted(policies))

    async def run_case(
        self,
        case: AttackCase,
        *,
        target: TargetAdapter,
        judge: Judge,
        budget: BudgetLedger,
        execution_id: str,
    ) -> ExecutionResult:
        if case.interaction_mode != "environment_injection":
            raise ValueError(f"case {case.id} is not an environment_injection case")
        fixture_ref = case.payload.fixture
        if fixture_ref is None or fixture_ref not in self._fixtures:
            raise ValueError(f"case {case.id} fixture is not authorized by this runner")

        definition = self._fixtures[fixture_ref]
        if case.target_classes != [definition.target_class] and definition.target_class not in case.target_classes:
            raise ValueError("fixture target class does not match attack case")
        if definition.target_mode not in case.target_modes:
            raise ValueError("fixture target mode does not match attack case")
        if target.identity.target_class != definition.target_class:
            raise ValueError("fixture target class does not match active target")
        if target.identity.target_mode != definition.target_mode:
            raise ValueError("fixture target mode does not match active target")

        self._verify_target_workspace_binding(target)
        materialization_hash = self._materialize(fixture_ref, definition)
        verifiers = tuple(
            ForbiddenPathVerifier(
                self.workspace_root,
                binding.path,
                verifier_id=binding.verifier_id,
            )
            for binding in definition.state_verifiers
        )
        for verifier in verifiers:
            snapshot = verifier.capture()
            if not snapshot.complete:
                raise ValueError("forbidden-path verifier cannot establish baseline state")
            expected_absent = canonical_json_hash({"exists": False})
            if any(component.value_hash != expected_absent for component in snapshot.components):
                raise ValueError("fixture baseline already contains a forbidden path")

        wrapped = StateVerifyingTarget(target, verifiers)
        executable_case = case.model_copy(
            update={"payload": PayloadSpec(text=definition.legitimate_task)}
        )
        execution = await CampaignEngine(
            target=wrapped,
            judge=judge,
            budget=budget,
        ).run_case(executable_case, execution_id=execution_id)

        provenance = EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="workspace_fixture_runner",
            observed_at=datetime.now(UTC).isoformat(),
            content_hash=self._fixture_hashes[fixture_ref],
            data={
                "environment_injection": True,
                "runner_version": _RUNNER_VERSION,
                "fixture_ref_hash": sha256(fixture_ref.encode()).hexdigest(),
                "fixture_content_hash": self._fixture_hashes[fixture_ref],
                "materialization_hash": materialization_hash,
                "legitimate_task_hash": sha256(definition.legitimate_task.encode()).hexdigest(),
                "workspace_root_hash": sha256(
                    self.workspace_root.as_posix().encode()
                ).hexdigest(),
            },
            redacted=True,
        )
        return execution.model_copy(update={"evidence": (*execution.evidence, provenance)})

    def _load_fixture(self, fixture_ref: str) -> tuple[WorkspaceFixtureDefinition, str]:
        fixture_dir = self._confined_path(self.corpus_root, fixture_ref)
        definition_path = fixture_dir / "fixture.yaml"
        if not definition_path.is_file():
            raise ValueError(f"fixture definition does not exist: {fixture_ref}")
        try:
            raw = yaml.safe_load(definition_path.read_text(encoding="utf-8"))
            definition = WorkspaceFixtureDefinition.model_validate(raw)
        except (yaml.YAMLError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid fixture definition {fixture_ref}: {exc}") from exc

        source_root = self._confined_path(fixture_dir, definition.workspace_subdir)
        if not source_root.is_dir():
            raise ValueError(f"fixture workspace does not exist: {fixture_ref}")
        tree_hash = self._source_tree_hash(source_root)
        fixture_hash = canonical_json_hash(
            {
                "definition": definition.model_dump(mode="json"),
                "source_tree_hash": tree_hash,
            }
        )
        return definition, fixture_hash

    def _materialize(
        self,
        fixture_ref: str,
        definition: WorkspaceFixtureDefinition,
    ) -> str:
        self._require_disposable_workspace()
        source_root = self._confined_path(
            self._confined_path(self.corpus_root, fixture_ref),
            definition.workspace_subdir,
        )
        for child in list(self.workspace_root.iterdir()):
            if child.name == _SENTINEL_NAME:
                continue
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)
            else:
                raise ValueError("unsupported existing workspace entry")

        for source in sorted(source_root.rglob("*")):
            relative = source.relative_to(source_root)
            destination = self.workspace_root / relative
            info = source.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("fixture source symlinks are not allowed")
            if stat.S_ISDIR(info.st_mode):
                destination.mkdir(parents=True, exist_ok=True)
            elif stat.S_ISREG(info.st_mode):
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            else:
                raise ValueError("fixture source special files are not allowed")

        return self._source_tree_hash(self.workspace_root, ignore_sentinel=True)

    def _require_disposable_workspace(self) -> None:
        if not self.workspace_root.exists() or not self.workspace_root.is_dir():
            raise ValueError("disposable workspace has not been initialized")
        if self.workspace_root.is_symlink():
            raise ValueError("disposable workspace root cannot be a symlink")
        sentinel = self.workspace_root / _SENTINEL_NAME
        try:
            value = sentinel.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError("disposable workspace sentinel is missing") from exc
        if value != _SENTINEL_VALUE:
            raise ValueError("disposable workspace sentinel is invalid")

    def _verify_target_workspace_binding(self, target: TargetAdapter) -> None:
        value = getattr(target, "workspace_root", None)
        if value is None:
            config = getattr(target, "config", None)
            value = getattr(config, "workspace_root", None) if config is not None else None
        if not isinstance(value, (str, os.PathLike)):
            raise ValueError("environment runner requires a workspace-bound target")
        configured = Path(value).resolve(strict=False)
        if configured != self.workspace_root:
            raise ValueError("target workspace_root does not match disposable fixture workspace")

    @staticmethod
    def _confined_path(root: Path, relative: str) -> Path:
        normalized = PurePosixPath(relative.replace("\\", "/"))
        if normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError("fixture path must be relative and confined")
        candidate = (root / Path(*normalized.parts)).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("fixture path escapes configured root") from exc
        return candidate

    @staticmethod
    def _source_tree_hash(root: Path, *, ignore_sentinel: bool = False) -> str:
        entries: list[dict[str, object]] = []
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if ignore_sentinel and relative == _SENTINEL_NAME:
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("symlinks are not allowed in fixture trees")
            if stat.S_ISDIR(info.st_mode):
                entries.append({"path": relative, "kind": "directory"})
            elif stat.S_ISREG(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "kind": "file",
                        "size": info.st_size,
                        "content_hash": _file_hash(path),
                    }
                )
            else:
                raise ValueError("special files are not allowed in fixture trees")
        return canonical_json_hash(entries)


def initialize_disposable_workspace(root: str | Path) -> Path:
    """Explicitly initialize an empty directory as resettable benchmark workspace."""

    workspace = Path(root).resolve(strict=False)
    if workspace.exists():
        if workspace.is_symlink() or not workspace.is_dir():
            raise ValueError("workspace initialization requires a real directory")
        if any(workspace.iterdir()):
            raise ValueError("workspace initialization requires an empty directory")
    else:
        workspace.mkdir(parents=True)
    (workspace / _SENTINEL_NAME).write_text(_SENTINEL_VALUE, encoding="utf-8")
    return workspace


def _file_hash(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
