"""Owned disposable workspaces for isolated Blue AGENT trials.

A Blue workspace is runtime state, not an attack fixture.  This supervisor materializes
one predeclared immutable template per trial under an explicitly owned sandbox root and
removes only paths whose exact lease is still active.  It performs no network operations.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_OWNERSHIP_MARKER = ".llm-redteam-blue-workspace-root-v1"
_OWNERSHIP_CONTENT = "llm-redteam-lab disposable Blue workspace root v1\n"


class DisposableWorkspaceProfile(StrictModel):
    """Stable policy for one immutable Blue workspace template."""

    version: int = Field(ge=1, default=1)
    template_sha256: str = Field(pattern=_HASH_PATTERN)
    symlink_policy: str = Field(default="reject")

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DisposableWorkspaceLease(StrictModel):
    """Hash-safe ownership token for one materialized trial workspace."""

    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_path_sha256: str = Field(pattern=_HASH_PATTERN)
    initial_tree_sha256: str = Field(pattern=_HASH_PATTERN)


class DisposableWorkspaceRelease(StrictModel):
    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    final_tree_sha256: str = Field(pattern=_HASH_PATTERN)
    teardown_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class PreparedDisposableWorkspace:
    """Ephemeral path plus persistence-safe lease evidence."""

    path: Path
    lease: DisposableWorkspaceLease


class DisposableWorkspaceSupervisor:
    """Materialize and remove immutable-template Blue workspaces fail closed."""

    def __init__(
        self,
        *,
        template_root: str | Path,
        sandbox_root: str | Path,
    ) -> None:
        self.template_root = Path(template_root).resolve(strict=False)
        self.sandbox_root = Path(sandbox_root).resolve(strict=False)
        if not self.template_root.is_dir():
            raise ValueError(f"template_root is not a directory: {self.template_root}")
        _reject_symlinks(self.template_root)
        self.profile = DisposableWorkspaceProfile(
            template_sha256=_tree_sha256(self.template_root)
        )
        self._active: dict[str, Path] = {}
        self._ensure_owned_root()

    def prepare(self, *, trial_id: str) -> PreparedDisposableWorkspace:
        if not trial_id:
            raise ValueError("trial_id must be non-empty")
        self._assert_ownership_marker()
        lease_id_hash = canonical_json_hash(
            {
                "workspace_profile_sha256": self.profile.profile_sha256,
                "trial_id": trial_id,
            }
        )
        if lease_id_hash in self._active:
            raise RuntimeError("workspace trial lease is already active")
        name = "trial-" + lease_id_hash[:24]
        destination = (self.sandbox_root / name).resolve(strict=False)
        if destination.parent != self.sandbox_root:
            raise RuntimeError("derived workspace path escaped sandbox root")
        if destination.exists():
            raise RuntimeError("derived workspace path already exists")

        try:
            shutil.copytree(self.template_root, destination, symlinks=False)
            _reject_symlinks(destination)
            initial_hash = _tree_sha256(destination)
            if initial_hash != self.profile.template_sha256:
                raise RuntimeError("materialized Blue workspace differs from immutable template")
        except Exception:
            if destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            raise

        self._active[lease_id_hash] = destination
        lease = DisposableWorkspaceLease(
            lease_id_hash=lease_id_hash,
            profile_sha256=self.profile.profile_sha256,
            workspace_path_sha256=sha256(str(destination).encode()).hexdigest(),
            initial_tree_sha256=initial_hash,
        )
        return PreparedDisposableWorkspace(path=destination, lease=lease)

    def release(self, prepared: PreparedDisposableWorkspace) -> DisposableWorkspaceRelease:
        self._assert_ownership_marker()
        lease = prepared.lease
        active = self._active.get(lease.lease_id_hash)
        if active is None:
            raise RuntimeError("workspace lease is not active")
        current = prepared.path.resolve(strict=False)
        if current != active:
            raise RuntimeError("workspace lease path changed")
        if current.parent != self.sandbox_root:
            raise RuntimeError("workspace lease escaped owned sandbox root")
        if sha256(str(current).encode()).hexdigest() != lease.workspace_path_sha256:
            raise RuntimeError("workspace lease path fingerprint changed")

        final_hash = (
            _tree_sha256(current)
            if current.exists()
            else canonical_json_hash({"workspace": "missing"})
        )
        cleanup_complete = True
        try:
            if current.exists():
                shutil.rmtree(current)
        except OSError:
            cleanup_complete = False
        if cleanup_complete:
            del self._active[lease.lease_id_hash]
        teardown = canonical_json_hash(
            {
                "lease_id_hash": lease.lease_id_hash,
                "workspace_path_sha256": lease.workspace_path_sha256,
                "final_tree_sha256": final_hash,
                "cleanup_complete": cleanup_complete,
            }
        )
        if not cleanup_complete:
            raise RuntimeError("Blue workspace cleanup failed")
        return DisposableWorkspaceRelease(
            lease_id_hash=lease.lease_id_hash,
            final_tree_sha256=final_hash,
            teardown_proof_sha256=teardown,
            cleanup_complete=True,
        )

    def _ensure_owned_root(self) -> None:
        if self.sandbox_root.exists() and not self.sandbox_root.is_dir():
            raise ValueError("Blue workspace sandbox_root must be a directory")
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        marker = self.sandbox_root / _OWNERSHIP_MARKER
        entries = [entry for entry in self.sandbox_root.iterdir() if entry != marker]
        if marker.exists():
            self._assert_ownership_marker()
            if entries:
                raise RuntimeError("owned Blue workspace root is not empty at initialization")
            return
        if entries:
            raise RuntimeError("non-empty Blue workspace root lacks laboratory ownership marker")
        marker.write_text(_OWNERSHIP_CONTENT, encoding="utf-8")

    def _assert_ownership_marker(self) -> None:
        marker = self.sandbox_root / _OWNERSHIP_MARKER
        try:
            content = marker.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("Blue workspace ownership marker is missing") from exc
        if content != _OWNERSHIP_CONTENT:
            raise RuntimeError("Blue workspace ownership marker is invalid")


def _reject_symlinks(root: Path) -> None:
    for directory, directories, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in (*directories, *files):
            if (base / name).is_symlink():
                raise ValueError("Blue workspace templates and materializations forbid symlinks")


def _tree_sha256(root: Path) -> str:
    if not root.is_dir():
        raise ValueError("workspace tree root must be a directory")
    rows: list[dict[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError("workspace tree hashing forbids symlinks")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            rows.append({"path": relative + "/", "kind": "directory"})
        elif path.is_file():
            rows.append(
                {
                    "path": relative,
                    "kind": "file",
                    "sha256": sha256(path.read_bytes()).hexdigest(),
                }
            )
        else:
            raise ValueError("workspace tree contains an unsupported filesystem entry")
    return canonical_json_hash(rows)
