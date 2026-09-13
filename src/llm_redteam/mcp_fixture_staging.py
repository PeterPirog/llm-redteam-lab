"""Control-plane staging boundary for synthetic MCP fixture context.

OpenCode's MCP configuration names paths in the target's filesystem namespace.  A Docker
control plane stages the corresponding files in a different host namespace and bind-mounts
them read-only into the target.  Treating one raw path as both identities is therefore
incorrect and, on Windows hosts, frequently impossible.

This module keeps those namespaces separate.  It performs no model or target call and does
not define Docker mounts.  The stable target-visible paths remain in
``McpFixtureBridgeProfile`` while a staging backend owns ephemeral host paths and emits only
hash-safe runtime binding/evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .opencode_runtime import McpFixtureBridgeProfile

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class McpFixtureRuntimeBinding(StrictModel):
    """Hash-only proof that host staging is mapped to one target-visible bridge policy."""

    version: int = Field(ge=1, default=1)
    bridge_sha256: str = Field(pattern=_HASH_PATTERN)
    staging_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    host_context_path_sha256: str = Field(pattern=_HASH_PATTERN)
    host_hash_path_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def binding_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class McpFixtureStageHandle:
    """Ephemeral control-plane handle; raw host paths must never be persisted."""

    stage_id_hash: str
    content_sha256: str
    host_context_path: Path
    host_hash_path: Path
    runtime_binding: McpFixtureRuntimeBinding


class McpFixtureStageRelease(StrictModel):
    """Persistence-safe result of clearing one staged synthetic MCP input."""

    stage_id_hash: str = Field(pattern=_HASH_PATTERN)
    integrity_preserved: bool
    cleanup_complete: bool
    cleanup_proof_sha256: str = Field(pattern=_HASH_PATTERN)


@runtime_checkable
class McpFixtureStagingBackend(Protocol):
    """Trusted control-plane backend for ephemeral MCP context sidecars."""

    @property
    def staging_policy_sha256(self) -> str: ...

    def runtime_binding(
        self,
        bridge: McpFixtureBridgeProfile,
    ) -> McpFixtureRuntimeBinding: ...

    def stage(
        self,
        *,
        bridge: McpFixtureBridgeProfile,
        content: str,
        content_sha256: str,
    ) -> McpFixtureStageHandle: ...

    def release(self, handle: McpFixtureStageHandle) -> McpFixtureStageRelease: ...


class FilesystemMcpFixtureStagingBackend:
    """Stage one context/hash pair in an explicitly owned host-side namespace.

    Host paths are runtime handles only.  The backend refuses pre-existing sidecars rather
    than overwriting them, uses exclusive file creation, verifies staged bytes before
    cleanup, and only removes files belonging to its active stage.
    """

    def __init__(
        self,
        *,
        context_host_path: str | Path,
        hash_host_path: str | Path,
        provider_id: str = "filesystem-mcp-staging-v1",
    ) -> None:
        if not provider_id:
            raise ValueError("MCP staging provider_id must be non-empty")
        context_path = Path(context_host_path).expanduser()
        hash_path = Path(hash_host_path).expanduser()
        if context_path == hash_path:
            raise ValueError("MCP host context and hash paths must be distinct")
        if context_path.exists() and context_path.is_dir():
            raise ValueError("MCP host context path cannot be a directory")
        if hash_path.exists() and hash_path.is_dir():
            raise ValueError("MCP host hash path cannot be a directory")
        for parent in {context_path.parent, hash_path.parent}:
            if not parent.exists() or not parent.is_dir() or parent.is_symlink():
                raise ValueError("MCP host staging parent must be an existing real directory")

        self._context_path = context_path.absolute()
        self._hash_path = hash_path.absolute()
        self._provider_id = provider_id
        self._counter = 0
        self._active: McpFixtureStageHandle | None = None
        self._staging_policy_sha256 = canonical_json_hash(
            {
                "version": 1,
                "provider_id": provider_id,
                "semantics": "exclusive-two-file-stage-verify-clear-v1",
            }
        )

    @classmethod
    def from_bridge_paths(
        cls,
        bridge: McpFixtureBridgeProfile,
        *,
        provider_id: str = "filesystem-mcp-staging-v1",
    ) -> FilesystemMcpFixtureStagingBackend:
        """Compatibility adapter for a trusted harness sharing one filesystem namespace."""

        return cls(
            context_host_path=bridge.context_file_path,
            hash_host_path=bridge.context_hash_file_path,
            provider_id=provider_id,
        )

    @property
    def staging_policy_sha256(self) -> str:
        return self._staging_policy_sha256

    @property
    def context_host_path(self) -> Path:
        """Runtime-only path used later as a Docker bind-mount source."""

        return self._context_path

    @property
    def hash_host_path(self) -> Path:
        """Runtime-only path used later as a Docker bind-mount source."""

        return self._hash_path

    def runtime_binding(
        self,
        bridge: McpFixtureBridgeProfile,
    ) -> McpFixtureRuntimeBinding:
        return McpFixtureRuntimeBinding(
            bridge_sha256=bridge.bridge_sha256,
            staging_policy_sha256=self._staging_policy_sha256,
            host_context_path_sha256=_path_sha256(self._context_path),
            host_hash_path_sha256=_path_sha256(self._hash_path),
        )

    def stage(
        self,
        *,
        bridge: McpFixtureBridgeProfile,
        content: str,
        content_sha256: str,
    ) -> McpFixtureStageHandle:
        if self._active is not None:
            raise RuntimeError("MCP staging backend already has an active context")
        observed_content_sha256 = sha256(content.encode()).hexdigest()
        if observed_content_sha256 != content_sha256:
            raise ValueError("MCP fixture context hash mismatch before host staging")
        if self._context_path.exists() or self._hash_path.exists():
            raise RuntimeError("MCP host sidecar already exists; stale/reused trial refused")

        binding = self.runtime_binding(bridge)
        self._counter += 1
        stage_id_hash = canonical_json_hash(
            {
                "runtime_binding_sha256": binding.binding_sha256,
                "content_sha256": content_sha256,
                "ordinal": self._counter,
            }
        )
        context_created = False
        hash_created = False
        try:
            with self._context_path.open("x", encoding="utf-8", newline="") as handle:
                handle.write(content)
            context_created = True
            with self._hash_path.open("x", encoding="ascii", newline="") as handle:
                handle.write(content_sha256 + "\n")
            hash_created = True
        except OSError:
            if hash_created:
                self._hash_path.unlink(missing_ok=True)
            if context_created:
                self._context_path.unlink(missing_ok=True)
            raise

        handle = McpFixtureStageHandle(
            stage_id_hash=stage_id_hash,
            content_sha256=content_sha256,
            host_context_path=self._context_path,
            host_hash_path=self._hash_path,
            runtime_binding=binding,
        )
        self._active = handle
        return handle

    def release(self, handle: McpFixtureStageHandle) -> McpFixtureStageRelease:
        if self._active is None or self._active.stage_id_hash != handle.stage_id_hash:
            raise RuntimeError("MCP staging handle does not match the active stage")
        if (
            handle.host_context_path != self._context_path
            or handle.host_hash_path != self._hash_path
        ):
            raise RuntimeError("MCP staging handle paths changed after admission")

        integrity_preserved = self._staged_integrity_matches(handle)
        cleanup_complete = True
        cleanup_error_types: list[str] = []
        for path in (self._context_path, self._hash_path):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                cleanup_complete = False
                cleanup_error_types.append(type(exc).__name__)
        if self._context_path.exists() or self._hash_path.exists():
            cleanup_complete = False
        if cleanup_complete:
            self._active = None

        proof = canonical_json_hash(
            {
                "stage_id_hash": handle.stage_id_hash,
                "runtime_binding_sha256": handle.runtime_binding.binding_sha256,
                "content_sha256": handle.content_sha256,
                "integrity_preserved": integrity_preserved,
                "cleanup_complete": cleanup_complete,
                "cleanup_error_types": sorted(cleanup_error_types),
            }
        )
        return McpFixtureStageRelease(
            stage_id_hash=handle.stage_id_hash,
            integrity_preserved=integrity_preserved,
            cleanup_complete=cleanup_complete,
            cleanup_proof_sha256=proof,
        )

    def _staged_integrity_matches(self, handle: McpFixtureStageHandle) -> bool:
        try:
            if not self._context_path.is_file() or not self._hash_path.is_file():
                return False
            observed_context = sha256(self._context_path.read_bytes()).hexdigest()
            observed_hash_text = self._hash_path.read_text(encoding="ascii").strip()
        except OSError:
            return False
        return (
            observed_context == handle.content_sha256
            and observed_hash_text == handle.content_sha256
        )


def _path_sha256(path: Path) -> str:
    return sha256(_normalized_host_path(path).encode()).hexdigest()


def _normalized_host_path(path: Path) -> str:
    value = str(path.absolute()).replace("\\", "/")
    if len(value) >= 2 and value[1] == ":":
        return value.casefold()
    if value.startswith("//"):
        return value.casefold()
    return value
