"""Fail-closed OpenCode launch profiles for authorized local AGENT campaigns.

This module does not start processes. It builds a deterministic launch contract that
must be paired with an independent sandbox attestation before a local OpenCode server
may be treated as a restricted Blue target. OpenCode permissions are defense in depth;
they are not used as proof of host/network containment.
"""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256
from ipaddress import ip_address
from urllib.parse import urlparse

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .targets.opencode import OpenCodeConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class SandboxEnforcementKind(StrEnum):
    """Trusted isolation mechanisms that may attest the OpenCode process boundary."""

    DOCKER = "docker"
    WINDOWS_SANDBOX = "windows_sandbox"
    OS_POLICY = "os_policy"
    TRUSTED_HARNESS = "trusted_harness"


class OpenCodeRuntimeProfile(StrictModel):
    """Deterministic security profile for one local headless OpenCode target."""

    version: int = Field(ge=1, default=1)
    executable: str = Field(min_length=1, default="opencode")
    workspace_root: str = Field(min_length=1)
    hostname: str = Field(min_length=1, default="127.0.0.1")
    port: int = Field(ge=1, le=65535, default=4096)
    shell_allowlist: tuple[str, ...] = ()
    server_password_env: str | None = None

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
                "pure": True,
                "share": "disabled",
                "autoupdate": False,
                "permission_policy": "deny-by-default-v1",
            }
        )

    def config_document(self) -> dict[str, object]:
        """Return a deny-by-default stable OpenCode configuration document.

        Shell permission is intentionally only a local application-layer guard. The
        independent sandbox attestation remains mandatory even when shell is denied.
        """

        shell_rules: dict[str, str] = {"*": "deny"}
        for pattern in self.shell_allowlist:
            shell_rules[pattern] = "allow"

        return {
            "$schema": "https://opencode.ai/config.json",
            "share": "disabled",
            "autoupdate": False,
            "permission": {
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
            },
        }

    def config_json(self) -> str:
        return json.dumps(self.config_document(), separators=(",", ":"), ensure_ascii=True)


class AgentSandboxAttestation(StrictModel):
    """Hash-only statement issued by a trusted isolation harness.

    The laboratory treats this as control-plane evidence. Red prompts, repository
    content, target output and OpenCode itself must never be allowed to mint or modify it.
    """

    version: int = Field(ge=1, default=1)
    issuer: str = Field(min_length=1)
    enforcement_kind: SandboxEnforcementKind
    isolation_id: str = Field(min_length=1)
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_root_sha256: str = Field(pattern=_HASH_PATTERN)
    proof_sha256: str = Field(pattern=_HASH_PATTERN)
    disposable_workspace: bool
    external_network_denied: bool
    git_publication_denied: bool
    allowed_network_endpoints: tuple[str, ...] = ()

    @model_validator(mode="after")
    def attestation_endpoints_are_local(self) -> AgentSandboxAttestation:
        for endpoint in self.allowed_network_endpoints:
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
                raise ValueError("allowed network endpoints must be HTTP(S) URLs")
            _require_loopback_host(parsed.hostname)
        return self

    @property
    def attestation_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class OpenCodeLaunchPlan(StrictModel):
    """Deterministic non-secret process launch contract."""

    cwd: str = Field(min_length=1)
    command: tuple[str, ...] = Field(min_length=1)
    public_environment: dict[str, str]
    required_secret_env_names: tuple[str, ...] = ()
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_attestation_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_root_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def launch_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def build_attested_opencode_launch_plan(
    profile: OpenCodeRuntimeProfile,
    attestation: AgentSandboxAttestation,
) -> OpenCodeLaunchPlan:
    """Bind OpenCode application controls to independent host/sandbox evidence."""

    if attestation.runtime_profile_sha256 != profile.profile_sha256:
        raise ValueError("sandbox attestation does not bind the requested runtime profile")
    if attestation.workspace_root_sha256 != profile.workspace_root_sha256:
        raise ValueError("sandbox attestation workspace does not match runtime profile")
    missing: list[str] = []
    if not attestation.disposable_workspace:
        missing.append("disposable_workspace")
    if not attestation.external_network_denied:
        missing.append("external_network_denied")
    if not attestation.git_publication_denied:
        missing.append("git_publication_denied")
    if missing:
        raise ValueError(
            "sandbox attestation is insufficient for restricted campaign: "
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
        sandbox_attestation_sha256=attestation.attestation_sha256,
        workspace_root_sha256=profile.workspace_root_sha256,
    )


def bind_attested_runtime_to_target(
    config: OpenCodeConfig,
    launch_plan: OpenCodeLaunchPlan,
) -> OpenCodeConfig:
    """Bind an OpenCode adapter identity to the attested process launch contract."""

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

    return config.model_copy(
        update={"runtime_attestation_fingerprint": launch_plan.launch_sha256}
    )


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
