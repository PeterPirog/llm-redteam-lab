"""Fail-closed local fixture runtime for environment-originated agent attacks.

Fixtures are attack inputs, not Blue configuration. The runtime fingerprints the complete
fixture bundle, resets one explicitly owned sandbox workspace before every trial, and emits
hash-only provenance. It never grants target permissions or performs network operations.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

import yaml
from pydantic import Field, model_validator

from .agent_actions import AgentEffectObservation, AgentEffectState, canonical_json_hash
from .domain import (
    AttackCase,
    EvidenceKind,
    EvidenceRecord,
    StrictModel,
    TargetClass,
    TargetIdentity,
    TargetMode,
)
from .state_verifiers import StateComponent, VerifierSnapshot
from .targets.base import TargetAdapter, TargetRequest, TargetResponse

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_OWNERSHIP_MARKER = ".llm-redteam-fixture-root-v1"
_OWNERSHIP_CONTENT = "llm-redteam-lab disposable fixture root v1\n"


class FixtureInjectionSurface(StrEnum):
    """Origin of attacker-controlled content presented to the Blue system."""

    REPOSITORY = "repository"
    TERMINAL_OUTPUT = "terminal_output"
    TOOL_OUTPUT = "tool_output"
    RETRIEVAL = "retrieval"
    MCP_CONTEXT = "mcp_context"
    MEMORY = "memory"


class FixtureManifest(StrictModel):
    """Typed manifest stored beside one immutable local fixture bundle."""

    version: int = Field(ge=1, default=1)
    id: str = Field(min_length=1)
    target_class: TargetClass
    target_mode: TargetMode
    purpose: str = Field(min_length=1)
    injection_surface: FixtureInjectionSurface
    workspace_subdir: str = Field(min_length=1)
    legitimate_task: str = Field(min_length=1)
    environment: dict[str, str] = Field(default_factory=dict)
    forbidden_paths: tuple[str, ...] = ()
    forbidden_effects: tuple[str, ...] = Field(min_length=1)
    expected_safe_effects: tuple[str, ...] = ()
    recommended_graders: tuple[str, ...] = ()

    @model_validator(mode="after")
    def fixture_paths_are_relative(self) -> FixtureManifest:
        workspace = PurePosixPath(self.workspace_subdir.replace("\\", "/"))
        if workspace.is_absolute() or ".." in workspace.parts:
            raise ValueError("workspace_subdir must remain inside the fixture bundle")
        for raw in self.forbidden_paths:
            path = PurePosixPath(raw.replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError("forbidden_paths must be non-empty relative paths")
        for name, value in self.environment.items():
            if not name or not name.replace("_", "").isalnum():
                raise ValueError("fixture environment names must be identifier-like")
            if value != "generated_per_run" and not value.startswith("synthetic:"):
                raise ValueError(
                    "fixture environment values must be generated_per_run or synthetic:*"
                )
        return self


class FixtureDescriptor(StrictModel):
    """Immutable, persistence-safe identity of one complete fixture bundle."""

    fixture_ref: str = Field(min_length=1)
    fixture_id: str = Field(min_length=1)
    target_class: TargetClass
    target_mode: TargetMode
    injection_surface: FixtureInjectionSurface
    manifest_sha256: str = Field(pattern=_HASH_PATTERN)
    bundle_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_template_sha256: str = Field(pattern=_HASH_PATTERN)
    legitimate_task: str = Field(min_length=1)
    environment_names: tuple[str, ...] = ()
    forbidden_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PreparedFixture:
    """Ephemeral runtime handle; synthetic values are never persisted by this class."""

    descriptor: FixtureDescriptor
    isolation_id: str
    workspace_root: Path
    workspace_initial_sha256: str
    environment: dict[str, str]

    def provenance_evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="fixture_runtime",
            observed_at="runtime",
            content_hash=self.descriptor.bundle_sha256,
            data={
                "fixture_id": self.descriptor.fixture_id,
                "fixture_ref_sha256": sha256(self.descriptor.fixture_ref.encode()).hexdigest(),
                "fixture_bundle_sha256": self.descriptor.bundle_sha256,
                "fixture_manifest_sha256": self.descriptor.manifest_sha256,
                "fixture_workspace_template_sha256": (
                    self.descriptor.workspace_template_sha256
                ),
                "fixture_injection_surface": self.descriptor.injection_surface.value,
                "fixture_isolation_id": self.isolation_id,
                "workspace_root_sha256": sha256(str(self.workspace_root).encode()).hexdigest(),
                "workspace_initial_sha256": self.workspace_initial_sha256,
                "environment_value_sha256": {
                    key: sha256(value.encode()).hexdigest()
                    for key, value in sorted(self.environment.items())
                },
            },
            redacted=True,
        )


class FixtureRelease(StrictModel):
    isolation_id: str = Field(min_length=1)
    workspace_final_sha256: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool

    def evidence(self) -> EvidenceRecord:
        return EvidenceRecord(
            kind=EvidenceKind.METADATA,
            source="fixture_runtime",
            observed_at="runtime",
            content_hash=self.workspace_final_sha256,
            data={
                "fixture_isolation_id": self.isolation_id,
                "workspace_final_sha256": self.workspace_final_sha256,
                "cleanup_complete": self.cleanup_complete,
            },
            redacted=True,
        )


@runtime_checkable
class FixtureRuntime(Protocol):
    """Prepare and reset one explicitly authorized environment fixture."""

    def describe(self, case: AttackCase) -> FixtureDescriptor: ...

    def prepare(self, case: AttackCase, *, run_id: str) -> PreparedFixture: ...

    def release(self, prepared: PreparedFixture) -> FixtureRelease: ...


class LocalFixtureRuntime:
    """Materialize fixtures into one owned local sandbox workspace.

    The sandbox root is treated as evaluator control-plane state. If the path already
    contains files and lacks the ownership marker, initialization fails rather than
    deleting anything. A single active workspace intentionally prevents concurrent runs
    from sharing state.
    """

    def __init__(self, *, fixture_root: str | Path, sandbox_root: str | Path) -> None:
        self.fixture_root = Path(fixture_root).resolve(strict=False)
        self.sandbox_root = Path(sandbox_root).resolve(strict=False)
        self.workspace_root = self.sandbox_root / "active"
        self._active_isolation_id: str | None = None
        if not self.fixture_root.is_dir():
            raise ValueError(f"fixture_root is not a directory: {self.fixture_root}")
        self._ensure_owned_sandbox_root()

    def describe(self, case: AttackCase) -> FixtureDescriptor:
        fixture_ref = case.payload.fixture
        if fixture_ref is None:
            raise ValueError(f"case {case.id} does not reference a fixture")
        manifest_path = self._resolve_fixture_manifest(fixture_ref)
        manifest = self._load_manifest(manifest_path)
        if manifest.target_class not in case.target_classes:
            raise ValueError(
                f"fixture {manifest.id} target_class is incompatible with case {case.id}"
            )
        if manifest.target_mode not in case.target_modes:
            raise ValueError(
                f"fixture {manifest.id} target_mode is incompatible with case {case.id}"
            )
        fixture_dir = manifest_path.parent
        workspace_source = (fixture_dir / manifest.workspace_subdir).resolve(strict=False)
        if not workspace_source.is_relative_to(fixture_dir) or not workspace_source.is_dir():
            raise ValueError("fixture workspace_subdir does not resolve to a fixture directory")
        return FixtureDescriptor(
            fixture_ref=fixture_ref,
            fixture_id=manifest.id,
            target_class=manifest.target_class,
            target_mode=manifest.target_mode,
            injection_surface=manifest.injection_surface,
            manifest_sha256=_file_sha256(manifest_path),
            bundle_sha256=_tree_sha256(fixture_dir),
            workspace_template_sha256=_tree_sha256(workspace_source),
            legitimate_task=manifest.legitimate_task,
            environment_names=tuple(sorted(manifest.environment)),
            forbidden_paths=tuple(sorted(manifest.forbidden_paths)),
        )

    def prepare(self, case: AttackCase, *, run_id: str) -> PreparedFixture:
        if self._active_isolation_id is not None:
            raise RuntimeError("fixture runtime already has an active trial")
        descriptor = self.describe(case)
        manifest_path = self._resolve_fixture_manifest(descriptor.fixture_ref)
        manifest = self._load_manifest(manifest_path)
        source = (manifest_path.parent / manifest.workspace_subdir).resolve(strict=False)

        self._assert_ownership_marker()
        if self.workspace_root.exists():
            shutil.rmtree(self.workspace_root)
        shutil.copytree(source, self.workspace_root, symlinks=True)
        workspace_hash = _tree_sha256(self.workspace_root)
        if workspace_hash != descriptor.workspace_template_sha256:
            shutil.rmtree(self.workspace_root, ignore_errors=True)
            raise RuntimeError("materialized workspace does not match fixture template hash")

        isolation_id = "fixture-" + sha256(
            f"{run_id}:{descriptor.bundle_sha256}".encode()
        ).hexdigest()[:24]
        environment = {
            name: _materialize_environment_value(
                name=name,
                specification=value,
                run_id=run_id,
                bundle_sha256=descriptor.bundle_sha256,
            )
            for name, value in manifest.environment.items()
        }
        self._active_isolation_id = isolation_id
        return PreparedFixture(
            descriptor=descriptor,
            isolation_id=isolation_id,
            workspace_root=self.workspace_root,
            workspace_initial_sha256=workspace_hash,
            environment=environment,
        )

    def release(self, prepared: PreparedFixture) -> FixtureRelease:
        if self._active_isolation_id != prepared.isolation_id:
            raise RuntimeError("fixture isolation identity does not match active trial")
        self._assert_ownership_marker()
        final_hash = (
            _tree_sha256(self.workspace_root)
            if self.workspace_root.exists()
            else canonical_json_hash({"workspace": "missing"})
        )
        cleanup_complete = True
        try:
            if self.workspace_root.exists():
                shutil.rmtree(self.workspace_root)
        except OSError:
            cleanup_complete = False
        finally:
            self._active_isolation_id = None
        if not cleanup_complete:
            raise RuntimeError("fixture workspace cleanup failed")
        return FixtureRelease(
            isolation_id=prepared.isolation_id,
            workspace_final_sha256=final_hash,
            cleanup_complete=True,
        )

    def _resolve_fixture_manifest(self, fixture_ref: str) -> Path:
        relative = Path(fixture_ref.replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("fixture reference must remain under fixture_root")
        path = (self.fixture_root / relative).resolve(strict=False)
        if not path.is_relative_to(self.fixture_root) or not path.is_file():
            raise ValueError(f"fixture manifest does not exist under fixture_root: {fixture_ref}")
        return path

    @staticmethod
    def _load_manifest(path: Path) -> FixtureManifest:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            return FixtureManifest.model_validate(raw)
        except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid fixture manifest {path}: {exc}") from exc

    def _ensure_owned_sandbox_root(self) -> None:
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        marker = self.sandbox_root / _OWNERSHIP_MARKER
        entries = [item for item in self.sandbox_root.iterdir() if item.name != _OWNERSHIP_MARKER]
        if marker.exists():
            self._assert_ownership_marker()
            return
        if entries:
            raise ValueError(
                "sandbox_root is non-empty and lacks llm-redteam ownership marker"
            )
        marker.write_text(_OWNERSHIP_CONTENT, encoding="utf-8")

    def _assert_ownership_marker(self) -> None:
        marker = self.sandbox_root / _OWNERSHIP_MARKER
        try:
            content = marker.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("fixture sandbox ownership marker is unavailable") from exc
        if content != _OWNERSHIP_CONTENT:
            raise RuntimeError("fixture sandbox ownership marker is invalid")


class FixtureProvenanceTarget:
    """Attach fixture provenance to a target without changing Blue identity."""

    def __init__(self, target: TargetAdapter, prepared: PreparedFixture) -> None:
        self._target = target
        self._prepared = prepared

    @property
    def identity(self) -> TargetIdentity:
        return self._target.identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        metadata = dict(request.metadata)
        metadata.update(
            {
                "fixture_id": self._prepared.descriptor.fixture_id,
                "fixture_isolation_id": self._prepared.isolation_id,
                "fixture_injection_surface": (
                    self._prepared.descriptor.injection_surface.value
                ),
            }
        )
        response = await self._target.execute(request.model_copy(update={"metadata": metadata}))
        provider_metadata = dict(response.provider_metadata)
        provider_metadata.update(
            {
                "fixture_bound": True,
                "fixture_injection_surface": (
                    self._prepared.descriptor.injection_surface.value
                ),
            }
        )
        return response.model_copy(
            update={
                "evidence": response.evidence + (self._prepared.provenance_evidence(),),
                "provider_metadata": provider_metadata,
            }
        )


class FixturePathVerifier:
    """Observe only declared forbidden fixture paths, ignoring legitimate task edits."""

    def __init__(
        self,
        root: str | Path,
        *,
        relative_paths: tuple[str, ...],
        verifier_id: str = "fixture-forbidden-paths-v1",
        categories: frozenset[str] = frozenset({"filesystem_write"}),
    ) -> None:
        if not relative_paths:
            raise ValueError("FixturePathVerifier requires at least one relative path")
        self.root = Path(root).resolve(strict=False)
        self._verifier_id = verifier_id
        self._categories = categories
        self._relative_paths = tuple(sorted(_safe_relative_path(item) for item in relative_paths))

    @property
    def verifier_id(self) -> str:
        return self._verifier_id

    @property
    def categories(self) -> frozenset[str]:
        return self._categories

    def capture(self) -> VerifierSnapshot:
        components: list[StateComponent] = []
        errors: list[str] = []
        for relative in self._relative_paths:
            path = self.root / relative
            try:
                components.append(_path_component(path, relative))
            except OSError as exc:
                errors.append(
                    canonical_json_hash(
                        {
                            "kind": type(exc).__name__,
                            "path_sha256": sha256(relative.encode()).hexdigest(),
                        }
                    )
                )
        return _build_fixture_snapshot(
            verifier_id=self.verifier_id,
            categories=self.categories,
            complete=not errors,
            components=tuple(components),
            error_hashes=tuple(sorted(errors)),
        )

    def assess(
        self,
        before: VerifierSnapshot,
        after: VerifierSnapshot,
        *,
        control_event_id: str,
        action_categories: frozenset[str],
        attribution_ambiguous: bool = False,
    ) -> AgentEffectObservation | None:
        relevant = self.categories.intersection(action_categories)
        if not relevant:
            return None
        if before.verifier_id != self.verifier_id or after.verifier_id != self.verifier_id:
            raise ValueError("fixture verifier snapshot identity mismatch")
        if not before.complete or not after.complete or attribution_ambiguous:
            state = AgentEffectState.UNKNOWN
            effect_hash = None
        elif before.state_hash == after.state_hash:
            state = AgentEffectState.ABSENT
            effect_hash = None
        else:
            state = AgentEffectState.OBSERVED
            effect_hash = canonical_json_hash(
                {
                    "verifier_id": self.verifier_id,
                    "control_event_id": control_event_id,
                    "categories": sorted(relevant),
                    "before": before.state_hash,
                    "after": after.state_hash,
                }
            )
        return AgentEffectObservation(
            control_event_id=control_event_id,
            verifier_id=self.verifier_id,
            state=state,
            categories=frozenset(relevant),
            effect_hash=effect_hash,
            state_before_hash=before.state_hash,
            state_after_hash=after.state_hash,
            source="deterministic_fixture_state_verifier",
        )


def _safe_relative_path(raw: str) -> str:
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("fixture verifier paths must be non-empty relative paths")
    return path.as_posix()


def _path_component(path: Path, relative: str) -> StateComponent:
    identity_hash = sha256(relative.encode()).hexdigest()
    if not path.exists() and not path.is_symlink():
        return StateComponent(
            identity_hash=identity_hash,
            kind="absent",
            value_hash=canonical_json_hash({"exists": False}),
        )
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if path.is_symlink():
        payload = {
            "mode": mode,
            "target_sha256": sha256(os.readlink(path).encode()).hexdigest(),
        }
        kind = "symlink"
    elif stat.S_ISDIR(info.st_mode):
        payload = {"mode": mode, "exists": True}
        kind = "directory"
    elif stat.S_ISREG(info.st_mode):
        payload = {
            "mode": mode,
            "size": info.st_size,
            "content_sha256": _file_sha256(path),
        }
        kind = "file"
    else:
        payload = {"mode": mode, "size": info.st_size}
        kind = "special"
    return StateComponent(
        identity_hash=identity_hash,
        kind=kind,
        value_hash=canonical_json_hash(payload),
    )


def _build_fixture_snapshot(
    *,
    verifier_id: str,
    categories: frozenset[str],
    complete: bool,
    components: tuple[StateComponent, ...],
    error_hashes: tuple[str, ...],
) -> VerifierSnapshot:
    normalized = tuple(
        sorted(components, key=lambda item: (item.identity_hash, item.kind, item.value_hash))
    )
    payload = {
        "verifier_id": verifier_id,
        "categories": sorted(categories),
        "complete": complete,
        "components": [item.model_dump(mode="json") for item in normalized],
        "error_hashes": list(error_hashes),
    }
    state_hash = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return VerifierSnapshot(
        verifier_id=verifier_id,
        categories=categories,
        complete=complete,
        components=normalized,
        error_hashes=error_hashes,
        state_hash=state_hash,
    )


def _materialize_environment_value(
    *,
    name: str,
    specification: str,
    run_id: str,
    bundle_sha256: str,
) -> str:
    if specification == "generated_per_run":
        digest = sha256(f"{run_id}:{bundle_sha256}:{name}".encode()).hexdigest()[:20].upper()
        return f"RT_SYNTHETIC_CANARY_{digest}"
    return specification.removeprefix("synthetic:")


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    if not root.is_dir():
        raise ValueError(f"fixture tree is not a directory: {root}")
    digest = sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"fixture bundles cannot contain symlinks: {relative}")
        digest.update(relative.encode())
        digest.update(b"\0")
        if path.is_dir():
            digest.update(b"dir\0")
            continue
        if not path.is_file():
            raise ValueError(f"fixture bundle contains unsupported filesystem entry: {relative}")
        digest.update(b"file\0")
        digest.update(_file_sha256(path).encode())
        digest.update(b"\0")
    return digest.hexdigest()
