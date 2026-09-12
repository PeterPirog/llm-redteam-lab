"""Fail-closed OpenCode runtime profiles for authorized local AGENT campaigns.

This module builds deterministic OpenCode launch policy and optional synthetic MCP
fixture transport. It does not start processes. OpenCode permissions are defense in
depth and are never treated as proof of host/network containment.
"""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlparse

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel, TargetIdentity
from .targets.base import (
    TargetRequest,
    TargetResponse,
    UntrustedContextChannel,
)
from .targets.opencode import OpenCodeConfig, OpenCodeTarget

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_MCP_CONTEXT_FILE_ENV = "LLM_REDTEAM_MCP_CONTEXT_FILE"
_MCP_CONTEXT_HASH_FILE_ENV = "LLM_REDTEAM_MCP_CONTEXT_HASH_FILE"


class SandboxEnforcementKind(StrEnum):
    """Trusted isolation mechanisms that may attest the OpenCode process boundary."""

    DOCKER = "docker"
    WINDOWS_SANDBOX = "windows_sandbox"
    OS_POLICY = "os_policy"
    TRUSTED_HARNESS = "trusted_harness"


class McpFixtureBridgeProfile(StrictModel):
    """Stable local MCP transport configuration for ephemeral fixture context."""

    version: int = Field(ge=1, default=1)
    server_name: str = Field(min_length=1, default="mcp_rt_fixture")
    python_executable: str = Field(min_length=1, default="python")
    context_file_path: str = Field(min_length=1)
    context_hash_file_path: str = Field(min_length=1)

    @model_validator(mode="after")
    def bridge_paths_and_name_are_valid(self) -> McpFixtureBridgeProfile:
        if not _identifier_like(self.server_name):
            raise ValueError("MCP fixture server_name must be identifier-like")
        if self.context_file_path == self.context_hash_file_path:
            raise ValueError("MCP context and hash sidecars must use distinct paths")
        if "\x00" in self.context_file_path or "\x00" in self.context_hash_file_path:
            raise ValueError("MCP sidecar paths cannot contain NUL")
        return self

    @property
    def tool_prefix(self) -> str:
        return f"{self.server_name}_*"

    @property
    def bridge_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "server_name": self.server_name,
                "python_executable": self.python_executable,
                "context_file_path_sha256": sha256(
                    _normalize_workspace(self.context_file_path).encode()
                ).hexdigest(),
                "context_hash_file_path_sha256": sha256(
                    _normalize_workspace(self.context_hash_file_path).encode()
                ).hexdigest(),
                "server_module": "llm_redteam.mcp_fixture_server",
                "transport": "stdio",
            }
        )

    def opencode_server_config(self) -> dict[str, object]:
        return {
            "type": "local",
            "command": [
                self.python_executable,
                "-m",
                "llm_redteam.mcp_fixture_server",
            ],
            "enabled": True,
            "environment": {
                _MCP_CONTEXT_FILE_ENV: self.context_file_path,
                _MCP_CONTEXT_HASH_FILE_ENV: self.context_hash_file_path,
            },
        }


class OpenCodeRuntimeProfile(StrictModel):
    """Deterministic application/runtime profile for one local headless OpenCode target."""

    version: int = Field(ge=1, default=1)
    executable: str = Field(min_length=1, default="opencode")
    workspace_root: str = Field(min_length=1)
    hostname: str = Field(min_length=1, default="127.0.0.1")
    port: int = Field(ge=1, le=65535, default=4096)
    shell_allowlist: tuple[str, ...] = ()
    server_password_env: str | None = None
    mcp_fixture_bridge: McpFixtureBridgeProfile | None = None

    @model_validator(mode="after")
    def restricted_profile_is_valid(self) -> OpenCodeRuntimeProfile:
        _require_loopback_host(self.hostname)
        if "\x00" in self.workspace_root:
            raise ValueError("workspace_root contains NUL")
        if self.server_password_env is not None and not _identifier_like(
            self.server_password_env
        ):
            raise ValueError("server_password_env must be identifier-like")
        normalized: list[str] = []
        for pattern in self.shell_allowlist:
            candidate = pattern.strip()
            if not candidate:
                raise ValueError("shell allowlist patterns cannot be empty")
            if candidate in normalized:
                raise ValueError("shell allowlist patterns must be unique")
            lowered = candidate.casefold()
            if any(
                token in lowered
                for token in (
                    "git push",
                    "curl ",
                    "wget ",
                    "invoke-webrequest",
                    "invoke-restmethod",
                    "ssh ",
                    "scp ",
                )
            ):
                raise ValueError(
                    "shell allowlist cannot explicitly authorize publication or network tools"
                )
            normalized.append(candidate)

        bridge = self.mcp_fixture_bridge
        if bridge is not None:
            if _path_is_within(bridge.context_file_path, self.workspace_root):
                raise ValueError("MCP context sidecar must remain outside Blue workspace")
            if _path_is_within(bridge.context_hash_file_path, self.workspace_root):
                raise ValueError("MCP hash sidecar must remain outside Blue workspace")
        return self

    @property
    def workspace_root_sha256(self) -> str:
        return sha256(_normalize_workspace(self.workspace_root).encode()).hexdigest()

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "executable": self.executable,
                "workspace_root_sha256": self.workspace_root_sha256,
                "hostname": self.hostname.casefold(),
                "port": self.port,
                "shell_allowlist": list(self.shell_allowlist),
                "server_password_env": self.server_password_env,
                "mcp_fixture_bridge_sha256": (
                    self.mcp_fixture_bridge.bridge_sha256
                    if self.mcp_fixture_bridge is not None
                    else None
                ),
                "pure": True,
                "share": "disabled",
                "autoupdate": False,
                "permission_policy": "deny-by-default-v1",
            }
        )

    def config_document(self) -> dict[str, object]:
        """Return a deny-by-default stable OpenCode configuration document."""

        shell_rules: dict[str, str] = {"*": "deny"}
        for pattern in self.shell_allowlist:
            shell_rules[pattern] = "allow"

        permissions: dict[str, object] = {
            "*": "deny",
            "read": {
                "*": "allow",
                "*.env": "deny",
                "*.env.*": "deny",
                "*.env.example": "allow",
            },
            "glob": "allow",
            "grep": "allow",
            "edit": "allow",
            "bash": shell_rules,
            "task": "deny",
            "webfetch": "deny",
            "websearch": "deny",
            "external_directory": "deny",
        }
        document: dict[str, object] = {
            "$schema": "https://opencode.ai/config.json",
            "share": "disabled",
            "autoupdate": False,
            "permission": permissions,
        }
        if self.mcp_fixture_bridge is not None:
            permissions[self.mcp_fixture_bridge.tool_prefix] = "allow"
            document["mcp"] = {
                self.mcp_fixture_bridge.server_name: (
                    self.mcp_fixture_bridge.opencode_server_config()
                )
            }
        return document

    def config_json(self) -> str:
        return json.dumps(self.config_document(), separators=(",", ":"), ensure_ascii=True)


class AgentSandboxPolicy(StrictModel):
    """Stable security policy that defines one Blue runtime configuration."""

    version: int = Field(ge=1, default=1)
    enforcement_kind: SandboxEnforcementKind
    enforcement_profile_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    disposable_workspace: bool = True
    external_network_denied: bool = True
    git_publication_denied: bool = True
    allowed_network_endpoints: tuple[str, ...] = ()

    @model_validator(mode="after")
    def policy_endpoints_are_local(self) -> AgentSandboxPolicy:
        for endpoint in self.allowed_network_endpoints:
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
                raise ValueError("allowed network endpoints must be HTTP(S) URLs")
            _require_loopback_host(parsed.hostname)
        return self

    @property
    def policy_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class AgentSandboxAttestation(StrictModel):
    """Per-run hash-only evidence issued by a trusted isolation harness."""

    version: int = Field(ge=1, default=1)
    issuer: str = Field(min_length=1)
    isolation_id: str = Field(min_length=1)
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_root_sha256: str = Field(pattern=_HASH_PATTERN)
    proof_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def attestation_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class OpenCodeLaunchPlan(StrictModel):
    """Deterministic non-secret process launch contract for one isolated run."""

    cwd: str = Field(min_length=1)
    command: tuple[str, ...] = Field(min_length=1)
    public_environment: dict[str, str]
    required_secret_env_names: tuple[str, ...] = ()
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_attestation_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_root_sha256: str = Field(pattern=_HASH_PATTERN)
    mcp_fixture_bridge_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)

    @property
    def launch_sha256(self) -> str:
        """Per-run execution fingerprint; may change across isolated replicates."""

        return canonical_json_hash(self.model_dump(mode="json"))

    @property
    def target_policy_sha256(self) -> str:
        """Stable identity of the security-relevant runtime policy."""

        return canonical_json_hash(
            {
                "runtime_profile_sha256": self.runtime_profile_sha256,
                "sandbox_policy_sha256": self.sandbox_policy_sha256,
                "workspace_root_sha256": self.workspace_root_sha256,
                "mcp_fixture_bridge_sha256": self.mcp_fixture_bridge_sha256,
            }
        )


class AttestedOpenCodeTarget:
    """OpenCode target bound to stable policy and one run-specific attestation."""

    def __init__(self, target: OpenCodeTarget, launch_plan: OpenCodeLaunchPlan) -> None:
        _validate_target_binding(target.config, launch_plan)
        self._target = target
        self.launch_plan = launch_plan

    @property
    def identity(self) -> TargetIdentity:
        base = self._target.identity
        return base.model_copy(
            update={
                "configuration_hash": canonical_json_hash(
                    {
                        "base_target_configuration_hash": base.configuration_hash,
                        "opencode_target_policy_sha256": (
                            self.launch_plan.target_policy_sha256
                        ),
                    }
                ),
                "capabilities": base.capabilities | frozenset({"runtime_attested"}),
            }
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        response = await self._target.execute(request)
        metadata = dict(response.provider_metadata)
        metadata.update(
            {
                "runtime_attested": True,
                "runtime_profile_sha256": self.launch_plan.runtime_profile_sha256,
                "sandbox_policy_sha256": self.launch_plan.sandbox_policy_sha256,
                "sandbox_attestation_sha256": self.launch_plan.sandbox_attestation_sha256,
                "launch_plan_sha256": self.launch_plan.launch_sha256,
            }
        )
        return response.model_copy(update={"provider_metadata": metadata})

    async def aclose(self) -> None:
        await self._target.aclose()


class McpContextOpenCodeTarget:
    """Transport `MCP_CONTEXT` through a real local MCP sidecar, never the user prompt."""

    def __init__(
        self,
        target: AttestedOpenCodeTarget,
        bridge: McpFixtureBridgeProfile,
    ) -> None:
        if target.launch_plan.mcp_fixture_bridge_sha256 != bridge.bridge_sha256:
            raise ValueError("OpenCode launch plan is not bound to this MCP fixture bridge")
        self._target = target
        self.bridge = bridge

    @property
    def identity(self) -> TargetIdentity:
        base = self._target.identity
        return base.model_copy(
            update={
                "capabilities": base.capabilities | frozenset({"untrusted_context", "mcp"})
            }
        )

    async def execute(self, request: TargetRequest) -> TargetResponse:
        if not request.untrusted_context:
            return await self._target.execute(request)
        if len(request.untrusted_context) != 1:
            raise ValueError("MCP fixture transport requires exactly one untrusted context item")
        context = request.untrusted_context[0]
        if context.channel != UntrustedContextChannel.MCP_CONTEXT:
            raise ValueError("MCP fixture transport accepts only mcp_context channel")

        self._stage_context(content=context.content, content_sha256=context.content_sha256)
        try:
            forwarded = request.model_copy(update={"untrusted_context": ()})
            response = await self._target.execute(forwarded)
        finally:
            self._clear_context()

        metadata = dict(response.provider_metadata)
        metadata.update(
            {
                "untrusted_context_transport": "mcp_stdio_sidecar_v1",
                "mcp_fixture_server": self.bridge.server_name,
                "mcp_fixture_content_sha256": context.content_sha256,
            }
        )
        return response.model_copy(update={"provider_metadata": metadata})

    async def aclose(self) -> None:
        self._clear_context(ignore_missing=True)
        await self._target.aclose()

    def _stage_context(self, *, content: str, content_sha256: str) -> None:
        content_path = Path(self.bridge.context_file_path)
        hash_path = Path(self.bridge.context_hash_file_path)
        if content_path.exists() or hash_path.exists():
            raise RuntimeError(
                "MCP fixture sidecar already exists; concurrent/reused trial refused"
            )
        if not content_path.parent.is_dir() or not hash_path.parent.is_dir():
            raise RuntimeError("MCP fixture sidecar parent directory must already exist")
        if sha256(content.encode()).hexdigest() != content_sha256:
            raise ValueError("MCP fixture context hash mismatch before transport")
        try:
            content_path.write_text(content, encoding="utf-8")
            hash_path.write_text(content_sha256 + "\n", encoding="ascii")
        except OSError:
            content_path.unlink(missing_ok=True)
            hash_path.unlink(missing_ok=True)
            raise

    def _clear_context(self, *, ignore_missing: bool = False) -> None:
        content_path = Path(self.bridge.context_file_path)
        hash_path = Path(self.bridge.context_hash_file_path)
        errors: list[OSError] = []
        for path in (content_path, hash_path):
            try:
                path.unlink(missing_ok=ignore_missing)
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError("MCP fixture sidecar cleanup failed") from errors[0]


def build_attested_opencode_launch_plan(
    profile: OpenCodeRuntimeProfile,
    sandbox_policy: AgentSandboxPolicy,
    attestation: AgentSandboxAttestation,
) -> OpenCodeLaunchPlan:
    """Bind stable runtime policy to independent per-run sandbox evidence."""

    if attestation.runtime_profile_sha256 != profile.profile_sha256:
        raise ValueError("sandbox attestation does not bind the requested runtime profile")
    if attestation.sandbox_policy_sha256 != sandbox_policy.policy_sha256:
        raise ValueError("sandbox attestation does not bind the requested sandbox policy")
    if attestation.workspace_root_sha256 != profile.workspace_root_sha256:
        raise ValueError("sandbox attestation workspace does not match runtime profile")

    missing: list[str] = []
    if not sandbox_policy.disposable_workspace:
        missing.append("disposable_workspace")
    if not sandbox_policy.external_network_denied:
        missing.append("external_network_denied")
    if not sandbox_policy.git_publication_denied:
        missing.append("git_publication_denied")
    if missing:
        raise ValueError(
            "sandbox policy is insufficient for restricted campaign: "
            + ", ".join(missing)
        )

    environment = {
        "OPENCODE_AUTO_SHARE": "false",
        "OPENCODE_DISABLE_AUTOUPDATE": "true",
        "OPENCODE_CONFIG_CONTENT": profile.config_json(),
    }
    required_secret_env_names = (
        (profile.server_password_env,) if profile.server_password_env is not None else ()
    )
    command = (
        profile.executable,
        "--pure",
        "serve",
        "--hostname",
        profile.hostname,
        "--port",
        str(profile.port),
    )
    return OpenCodeLaunchPlan(
        cwd=profile.workspace_root,
        command=command,
        public_environment=environment,
        required_secret_env_names=required_secret_env_names,
        runtime_profile_sha256=profile.profile_sha256,
        sandbox_policy_sha256=sandbox_policy.policy_sha256,
        sandbox_attestation_sha256=attestation.attestation_sha256,
        workspace_root_sha256=profile.workspace_root_sha256,
        mcp_fixture_bridge_sha256=(
            profile.mcp_fixture_bridge.bridge_sha256
            if profile.mcp_fixture_bridge is not None
            else None
        ),
    )


def _validate_target_binding(
    config: OpenCodeConfig,
    launch_plan: OpenCodeLaunchPlan,
) -> None:
    if config.workspace_root is None:
        raise ValueError("attested OpenCode target requires workspace_root")
    workspace_hash = sha256(_normalize_workspace(config.workspace_root).encode()).hexdigest()
    if workspace_hash != launch_plan.workspace_root_sha256:
        raise ValueError("OpenCode target workspace does not match attested launch plan")

    parsed = urlparse(config.base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("OpenCode target base_url must be an HTTP(S) URL")
    _require_loopback_host(parsed.hostname)
    command_host, command_port = _launch_endpoint(launch_plan.command)
    if parsed.hostname.casefold() != command_host.casefold():
        raise ValueError("OpenCode target host does not match attested launch plan")
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if target_port != command_port:
        raise ValueError("OpenCode target port does not match attested launch plan")

    if launch_plan.required_secret_env_names:
        if config.password_env not in launch_plan.required_secret_env_names:
            raise ValueError("OpenCode target password_env is not bound to launch plan")
    elif config.password_env is not None:
        raise ValueError("OpenCode target requires a password not declared by launch plan")


def _launch_endpoint(command: tuple[str, ...]) -> tuple[str, int]:
    try:
        host_index = command.index("--hostname") + 1
        port_index = command.index("--port") + 1
        host = command[host_index]
        port = int(command[port_index])
    except (ValueError, IndexError) as exc:
        raise ValueError("launch plan command lacks a valid hostname/port") from exc
    _require_loopback_host(host)
    return host, port


def _require_loopback_host(hostname: str) -> None:
    normalized = hostname.strip().casefold()
    if normalized == "localhost":
        return
    try:
        address = ip_address(normalized)
    except ValueError as exc:
        raise ValueError("OpenCode server must bind to an explicit loopback host") from exc
    if not address.is_loopback:
        raise ValueError("OpenCode server must bind to loopback only")


def _identifier_like(value: str) -> bool:
    return bool(value) and (value[0].isalpha() or value[0] == "_") and all(
        character.isalnum() or character == "_" for character in value
    )


def _normalize_workspace(value: str) -> str:
    normalized = value.strip().replace("\\", "/").rstrip("/")
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.casefold()
    if normalized.startswith("//"):
        normalized = normalized.casefold()
    if not normalized:
        raise ValueError("workspace_root cannot normalize to empty")
    return normalized


def _path_is_within(candidate: str, root: str) -> bool:
    normalized_candidate = candidate.replace("\\", "/")
    normalized_root = root.replace("\\", "/")
    windows = (
        (len(normalized_candidate) >= 2 and normalized_candidate[1] == ":")
        or (len(normalized_root) >= 2 and normalized_root[1] == ":")
        or normalized_candidate.startswith("//")
        or normalized_root.startswith("//")
    )
    path_type = PureWindowsPath if windows else PurePosixPath
    path = path_type(candidate)
    root_path = path_type(root)
    try:
        path.relative_to(root_path)
    except ValueError:
        return False
    return True
