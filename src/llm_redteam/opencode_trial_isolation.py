"""Disposable per-trial OpenCode AGENT isolation on an owned Docker model network.

The provider in this module implements the generic ``TargetTrialLeaseProvider`` contract
for real coding-agent trials.  Each acquired lease receives a fresh host workspace and a
new hardened OpenCode container.  The campaign-scoped model network/model peer are reused,
but the Blue application state that can be influenced by an attacker is not.

No inference is performed by acquisition.  Before a target is returned, the trusted
control plane verifies Docker ownership, sandbox/network attestation, exact OpenCode
process configuration, server health/version and the stable Blue target identity.
"""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import time
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_exec_http import DockerExecContainerRef, DockerExecHttpProfile
from .docker_exec_opencode import build_attested_docker_exec_opencode_target
from .docker_model_network import (
    DockerIsolatedModelNetworkProfile,
)
from .docker_model_network_supervisor import DockerModelNetworkLease
from .docker_networked_supervisor import (
    DockerNetworkedAgentLease,
    DockerNetworkedAgentSupervisor,
)
from .docker_supervisor import DockerCommandRunner
from .domain import StrictModel, TargetClass, TargetIdentity, TargetMode
from .opencode_health import HealthGatedOpenCodeTarget, OpenCodeHealthObservation
from .opencode_prelaunch import (
    DockerOpenCodeNetworkedAgentProfile,
    bind_attested_opencode_launch,
    build_opencode_prelaunch_contract,
    verify_opencode_docker_process,
)
from .opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeLaunchPlan,
    OpenCodeRuntimeProfile,
    build_attested_opencode_launch_plan,
)
from .target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialIsolationAttestation,
    TargetTrialIsolationRelease,
    TargetTrialLease,
)
from .targets.base import TargetAdapter, TargetRequest, TargetResponse
from .targets.opencode import OpenCodeConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"

_HEALTH_SCRIPT = (
    "import base64,json,os,sys,urllib.error,urllib.request;"
    "url=sys.argv[1];password_env=sys.argv[2];username=sys.argv[3];"
    "req=urllib.request.Request(url,method='GET');"
    "password=os.getenv(password_env) if password_env else None;"
    "auth=base64.b64encode((username+':'+password).encode()).decode() if password else '';"
    "req.add_header('Authorization','Basic '+auth) if auth else None;"
    "r=urllib.request.urlopen(req,timeout=10);"
    "status=r.status;data=r.read();r.close();"
    "print(json.dumps({'status':status,'body_b64':base64.b64encode(data).decode()},"
    "separators=(',',':')))"
)


class DisposableWorkspaceLease(StrictModel):
    """Control-plane handle for one fresh workspace; raw path is runtime-only."""

    workspace_id_hash: str = Field(pattern=_HASH_PATTERN)
    host_path: str = Field(min_length=1)
    fresh_state_proof_hash: str = Field(pattern=_HASH_PATTERN)


class DisposableWorkspaceRelease(StrictModel):
    workspace_id_hash: str = Field(pattern=_HASH_PATTERN)
    teardown_proof_hash: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool


@runtime_checkable
class DisposableWorkspaceProvider(Protocol):
    @property
    def provider_fingerprint(self) -> str: ...

    def acquire(self, *, trial_id: str) -> DisposableWorkspaceLease: ...

    def release(self, lease: DisposableWorkspaceLease) -> DisposableWorkspaceRelease: ...


class FilesystemDisposableWorkspaceProvider:
    """Create empty, never-reused workspace directories below one trusted root.

    This provider deliberately does not copy a repository or fixture into the workspace.
    Repository/fixture materialization is a separate trusted-input concern so attacker-
    controlled content cannot silently broaden filesystem access during acquisition.
    """

    def __init__(self, root: str | Path, *, provider_id: str = "filesystem-empty-v1") -> None:
        if not provider_id:
            raise ValueError("workspace provider_id must be non-empty")
        root_path = Path(root).expanduser()
        root_path.mkdir(parents=True, exist_ok=True)
        resolved = root_path.resolve(strict=True)
        if not resolved.is_dir() or resolved.is_symlink():
            raise ValueError("workspace root must be a real directory, not a symlink")
        self._root = resolved
        self._provider_id = provider_id
        self._provider_fingerprint = canonical_json_hash(
            {
                "kind": "filesystem-empty-workspace-v1",
                "provider_id": provider_id,
                "root_sha256": sha256(_normalized_path(resolved).encode()).hexdigest(),
            }
        )
        self._active: dict[str, Path] = {}

    @property
    def provider_fingerprint(self) -> str:
        return self._provider_fingerprint

    def acquire(self, *, trial_id: str) -> DisposableWorkspaceLease:
        if not trial_id:
            raise ValueError("workspace trial_id must be non-empty")
        created = Path(tempfile.mkdtemp(prefix="llmrt-trial-", dir=self._root))
        resolved = created.resolve(strict=True)
        try:
            resolved.relative_to(self._root)
        except ValueError as exc:
            shutil.rmtree(resolved, ignore_errors=True)
            raise RuntimeError("workspace escaped the configured root") from exc
        if resolved.is_symlink() or any(resolved.iterdir()):
            shutil.rmtree(resolved, ignore_errors=True)
            raise RuntimeError("new disposable workspace is not an empty real directory")

        workspace_id_hash = sha256(_normalized_path(resolved).encode()).hexdigest()
        if workspace_id_hash in self._active:
            shutil.rmtree(resolved, ignore_errors=True)
            raise RuntimeError("workspace provider reused an active workspace identity")
        fresh_state_proof_hash = canonical_json_hash(
            {
                "provider_fingerprint": self._provider_fingerprint,
                "workspace_id_hash": workspace_id_hash,
                "trial_id_sha256": sha256(trial_id.encode()).hexdigest(),
                "initial_state": "empty-directory-v1",
            }
        )
        self._active[workspace_id_hash] = resolved
        return DisposableWorkspaceLease(
            workspace_id_hash=workspace_id_hash,
            host_path=str(resolved),
            fresh_state_proof_hash=fresh_state_proof_hash,
        )

    def release(self, lease: DisposableWorkspaceLease) -> DisposableWorkspaceRelease:
        path = self._active.get(lease.workspace_id_hash)
        if path is None:
            raise RuntimeError("workspace lease is not active")
        if str(path) != lease.host_path:
            raise RuntimeError("workspace lease path changed")
        try:
            path.relative_to(self._root)
        except ValueError as exc:
            raise RuntimeError("workspace lease is outside configured root") from exc
        if path.is_symlink():
            return self._release_result(lease, cleanup_complete=False, state="root-became-symlink")

        try:
            shutil.rmtree(path)
        except OSError:
            return self._release_result(lease, cleanup_complete=False, state="remove-failed")
        if path.exists():
            return self._release_result(lease, cleanup_complete=False, state="still-exists")
        del self._active[lease.workspace_id_hash]
        return self._release_result(lease, cleanup_complete=True, state="removed")

    def _release_result(
        self,
        lease: DisposableWorkspaceLease,
        *,
        cleanup_complete: bool,
        state: str,
    ) -> DisposableWorkspaceRelease:
        return DisposableWorkspaceRelease(
            workspace_id_hash=lease.workspace_id_hash,
            teardown_proof_hash=canonical_json_hash(
                {
                    "provider_fingerprint": self._provider_fingerprint,
                    "workspace_id_hash": lease.workspace_id_hash,
                    "state": state,
                    "cleanup_complete": cleanup_complete,
                }
            ),
            cleanup_complete=cleanup_complete,
        )


class DeclaredIsolatedOpenCodeTarget:
    """Stable target descriptor that refuses execution outside a trial lease."""

    def __init__(self, identity: TargetIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> TargetIdentity:
        return self._identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        del request
        return TargetResponse(error_kind="isolation:disposable_trial_lease_required")


@dataclass(slots=True)
class _ActiveOpenCodeTrial:
    target: TargetAdapter
    workspace: DisposableWorkspaceLease
    agent: DockerNetworkedAgentLease
    agent_released: bool = False
    workspace_released: bool = False
    workspace_release_proof: str | None = None


class DockerOpenCodeTrialLeaseProvider:
    """Issue one fresh hardened OpenCode container/workspace per AGENT trial."""

    def __init__(
        self,
        *,
        provider_id: str,
        workspace_provider: DisposableWorkspaceProvider,
        agent_supervisor: DockerNetworkedAgentSupervisor,
        runner: DockerCommandRunner,
        docker_profile: DockerOpenCodeNetworkedAgentProfile,
        model_network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
        model_peer_container_id_sha256: str,
        runtime_profile: OpenCodeRuntimeProfile,
        sandbox_policy: AgentSandboxPolicy,
        opencode_config: OpenCodeConfig,
        command_timeout_seconds: float = 15.0,
        health_attempts: int = 20,
        health_retry_seconds: float = 0.25,
    ) -> None:
        if not provider_id:
            raise ValueError("target isolation provider_id must be non-empty")
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        if health_attempts < 1:
            raise ValueError("health_attempts must be positive")
        if health_retry_seconds < 0:
            raise ValueError("health_retry_seconds cannot be negative")
        if runtime_profile.mcp_fixture_bridge is not None:
            raise ValueError(
                "Docker OpenCode trial leases do not yet support MCP sidecars; "
                "compound fixture/target isolation is required"
            )
        expected_prelaunch = build_opencode_prelaunch_contract(runtime_profile)
        if docker_profile.runtime_launch != expected_prelaunch:
            raise ValueError("Docker profile does not bind the requested OpenCode prelaunch")
        if sandbox_policy.enforcement_profile_sha256 != docker_profile.profile_sha256:
            raise ValueError("sandbox policy does not bind the Docker OpenCode profile")
        if not sandbox_policy.disposable_workspace:
            raise ValueError("OpenCode trial provider requires disposable_workspace")
        if not sandbox_policy.external_network_denied or sandbox_policy.allowed_network_endpoints:
            raise ValueError("OpenCode trial provider requires model-only isolated networking")
        if not sandbox_policy.git_publication_denied:
            raise ValueError("OpenCode trial provider requires git publication denial")
        if opencode_config.workspace_root != runtime_profile.workspace_root:
            raise ValueError("OpenCode target workspace does not match runtime profile")
        if opencode_config.application_version is None:
            raise ValueError("OpenCode disposable target requires pinned application_version")
        if len(model_peer_container_id_sha256) != 64:
            raise ValueError("model peer container identity must be a sha256 hex digest")

        self._workspace_provider = workspace_provider
        self._agent_supervisor = agent_supervisor
        self._runner = runner
        self.docker_profile = docker_profile
        self.model_network_profile = model_network_profile
        self.network_lease = network_lease
        self.model_peer_container_id_sha256 = model_peer_container_id_sha256
        self.runtime_profile = runtime_profile
        self.sandbox_policy = sandbox_policy
        self.opencode_config = opencode_config
        self._command_timeout_seconds = command_timeout_seconds
        self._health_attempts = health_attempts
        self._health_retry_seconds = health_retry_seconds
        self._counter = 0
        self._active: dict[str, _ActiveOpenCodeTrial] = {}
        self._provider_fingerprint = canonical_json_hash(
            {
                "kind": "docker-opencode-disposable-target-lease-v1",
                "provider_id": provider_id,
                "workspace_provider_fingerprint": workspace_provider.provider_fingerprint,
                "docker_profile_sha256": docker_profile.profile_sha256,
                "model_network_profile_sha256": model_network_profile.profile_sha256,
                "runtime_profile_sha256": runtime_profile.profile_sha256,
                "sandbox_policy_sha256": sandbox_policy.policy_sha256,
                "opencode_target_configuration_hash": _base_opencode_identity(
                    opencode_config
                ).configuration_hash,
                "health_attempts": health_attempts,
                "health_retry_seconds": health_retry_seconds,
            }
        )
        self._declared_identity = _declared_target_identity(
            opencode_config=opencode_config,
            runtime_profile=runtime_profile,
            sandbox_policy=sandbox_policy,
        )
        self._declared_target = DeclaredIsolatedOpenCodeTarget(self._declared_identity)

    @property
    def provider_fingerprint(self) -> str:
        return self._provider_fingerprint

    @property
    def isolation_level(self) -> TargetIsolationLevel:
        return TargetIsolationLevel.DISPOSABLE_SANDBOX

    @property
    def declared_target(self) -> TargetAdapter:
        """Target descriptor for campaign planning; direct execution is fail-closed."""

        return self._declared_target

    def acquire(
        self,
        *,
        expected_identity: TargetIdentity,
        trial_id: str,
    ) -> TargetTrialLease:
        if expected_identity != self._declared_identity:
            raise ValueError("expected Blue target does not match disposable provider policy")
        if not trial_id:
            raise ValueError("target trial_id must be non-empty")

        workspace = self._workspace_provider.acquire(trial_id=trial_id)
        agent: DockerNetworkedAgentLease | None = None
        try:
            self._counter += 1
            container_name = "llmrt-agent-" + canonical_json_hash(
                {
                    "provider_fingerprint": self._provider_fingerprint,
                    "trial_id_sha256": sha256(trial_id.encode()).hexdigest(),
                    "ordinal": self._counter,
                }
            )[:24]
            agent = self._agent_supervisor.launch(
                docker_profile=self.docker_profile,
                model_network_profile=self.model_network_profile,
                network_lease=self.network_lease,
                model_peer_container_id_sha256=self.model_peer_container_id_sha256,
                runtime_profile=self.runtime_profile,
                sandbox_policy=self.sandbox_policy,
                workspace_host_path=workspace.host_path,
                container_name=container_name,
                command=self.docker_profile.runtime_launch.command,
            )
            raw_inspection = self._inspect_owned_container(agent)
            process = verify_opencode_docker_process(
                payload=raw_inspection,
                prelaunch=self.docker_profile.runtime_launch,
            )
            launch_plan = build_attested_opencode_launch_plan(
                self.runtime_profile,
                self.sandbox_policy,
                agent.sandbox_attestation,
            )
            launch_binding = bind_attested_opencode_launch(
                prelaunch=self.docker_profile.runtime_launch,
                sandbox_policy=self.sandbox_policy,
                launch_plan=launch_plan,
            )
            container_ref = DockerExecContainerRef(
                container_name=agent.container_name,
                container_id_sha256=agent.container_id_sha256,
            )
            target = build_attested_docker_exec_opencode_target(
                config=self.opencode_config,
                runtime_profile=self.runtime_profile,
                launch_plan=launch_plan,
                container=container_ref,
                runner=self._runner,
            )
            health = self._probe_health(agent=agent, launch_plan=launch_plan)
            gated_target = HealthGatedOpenCodeTarget(target, health)
            if gated_target.identity != expected_identity:
                raise ValueError(
                    "constructed disposable OpenCode target differs from declared identity"
                )

            fresh_state_proof_hash = canonical_json_hash(
                {
                    "workspace_fresh_state_proof_hash": workspace.fresh_state_proof_hash,
                    "agent_container_id_sha256": agent.container_id_sha256,
                    "agent_launch_command_sha256": agent.launch_command_sha256,
                    "network_id_sha256": agent.network_id_sha256,
                    "sandbox_attestation_sha256": agent.sandbox_attestation.attestation_sha256,
                    "network_attestation_sha256": agent.network_attestation.attestation_sha256,
                    "process_observation_sha256": process.proof_sha256,
                    "launch_binding_sha256": launch_binding.proof_sha256,
                    "health_proof_sha256": health.proof_sha256,
                    "target_configuration_hash": expected_identity.configuration_hash,
                }
            )
            lease_id_hash = canonical_json_hash(
                {
                    "provider_fingerprint": self._provider_fingerprint,
                    "trial_id_sha256": sha256(trial_id.encode()).hexdigest(),
                    "fresh_state_proof_hash": fresh_state_proof_hash,
                }
            )
            if lease_id_hash in self._active:
                raise RuntimeError("target isolation lease identity was reused")
            self._active[lease_id_hash] = _ActiveOpenCodeTrial(
                target=gated_target,
                workspace=workspace,
                agent=agent,
            )
            return TargetTrialLease(
                target=gated_target,
                attestation=TargetTrialIsolationAttestation(
                    lease_id_hash=lease_id_hash,
                    provider_fingerprint=self._provider_fingerprint,
                    isolation_level=TargetIsolationLevel.DISPOSABLE_SANDBOX,
                    target_configuration_hash=expected_identity.configuration_hash,
                    fresh_state_proof_hash=fresh_state_proof_hash,
                    control_plane_independent=True,
                ),
            )
        except Exception as exc:
            cleanup_ok = self._cleanup_failed_acquisition(workspace=workspace, agent=agent)
            if not cleanup_ok:
                raise RuntimeError(
                    "OpenCode trial acquisition failed and cleanup was incomplete"
                ) from exc
            raise

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        lease_id_hash = lease.attestation.lease_id_hash
        active = self._active.get(lease_id_hash)
        if active is None:
            raise RuntimeError("target isolation lease is not active")
        if active.target is not lease.target:
            raise RuntimeError("target isolation lease target changed")

        if not active.agent_released:
            try:
                self._agent_supervisor.release(active.agent)
            except Exception:
                pass
            else:
                active.agent_released = True

        if active.agent_released and not active.workspace_released:
            workspace_release = self._workspace_provider.release(active.workspace)
            active.workspace_release_proof = workspace_release.teardown_proof_hash
            active.workspace_released = workspace_release.cleanup_complete

        cleanup_complete = active.agent_released and active.workspace_released
        teardown_proof_hash = canonical_json_hash(
            {
                "lease_id_hash": lease_id_hash,
                "provider_fingerprint": self._provider_fingerprint,
                "agent_container_id_sha256": active.agent.container_id_sha256,
                "agent_released": active.agent_released,
                "workspace_id_hash": active.workspace.workspace_id_hash,
                "workspace_released": active.workspace_released,
                "workspace_release_proof": active.workspace_release_proof,
                "cleanup_complete": cleanup_complete,
            }
        )
        if cleanup_complete:
            del self._active[lease_id_hash]
        return TargetTrialIsolationRelease(
            lease_id_hash=lease_id_hash,
            teardown_proof_hash=teardown_proof_hash,
            cleanup_complete=cleanup_complete,
        )

    def _cleanup_failed_acquisition(
        self,
        *,
        workspace: DisposableWorkspaceLease,
        agent: DockerNetworkedAgentLease | None,
    ) -> bool:
        agent_removed = agent is None
        if agent is not None:
            try:
                self._agent_supervisor.release(agent)
            except Exception:
                agent_removed = False
            else:
                agent_removed = True
        if not agent_removed:
            return False
        try:
            workspace_release = self._workspace_provider.release(workspace)
        except Exception:
            return False
        return workspace_release.cleanup_complete

    def _inspect_owned_container(
        self,
        agent: DockerNetworkedAgentLease,
    ) -> dict[str, object]:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", agent.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("OpenCode trial container is not inspectable")
        try:
            payload = json.loads(result.stdout)
            if not isinstance(payload, list) or len(payload) != 1:
                raise ValueError("inspect cardinality")
            record = payload[0]
            if not isinstance(record, dict):
                raise ValueError("inspect shape")
            container_id = record.get("Id")
            if not isinstance(container_id, str):
                raise ValueError("inspect ID")
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("OpenCode trial inspect payload is invalid") from exc
        if sha256(container_id.encode()).hexdigest() != agent.container_id_sha256:
            raise RuntimeError("OpenCode trial container ownership changed")
        return record

    def _probe_health(
        self,
        *,
        agent: DockerNetworkedAgentLease,
        launch_plan: OpenCodeLaunchPlan,
    ) -> OpenCodeHealthObservation:
        endpoint = (
            f"http://{self.runtime_profile.hostname}:"
            f"{self.runtime_profile.port}/global/health"
        )
        last_error: Exception | None = None
        for attempt in range(self._health_attempts):
            try:
                self._inspect_owned_container(agent)
                result = self._runner.run(
                    (
                        "docker",
                        "exec",
                        agent.container_name,
                        "python",
                        "-c",
                        _HEALTH_SCRIPT,
                        endpoint,
                        self.runtime_profile.server_password_env or "",
                        self.opencode_config.username,
                    ),
                    timeout_seconds=self._command_timeout_seconds,
                )
                if result.returncode != 0:
                    raise RuntimeError("OpenCode health command failed")
                envelope = json.loads(result.stdout.strip())
                if not isinstance(envelope, dict) or envelope.get("status") != 200:
                    raise ValueError("OpenCode health returned non-200 status")
                body_raw = envelope.get("body_b64")
                if not isinstance(body_raw, str):
                    raise ValueError("OpenCode health response body is missing")
                body_bytes = base64.b64decode(body_raw, validate=True)
                body = json.loads(body_bytes)
                if not isinstance(body, dict):
                    raise ValueError("OpenCode health body is not an object")
                healthy = body.get("healthy")
                version = body.get("version")
                if healthy is not True or not isinstance(version, str) or not version:
                    raise ValueError("OpenCode health response is unhealthy or lacks version")
                if version != self.opencode_config.application_version:
                    raise ValueError("OpenCode health version does not match pinned target version")
                self._inspect_owned_container(agent)
                return OpenCodeHealthObservation(
                    healthy=True,
                    application_version=version,
                    runtime_profile_sha256=self.runtime_profile.profile_sha256,
                    sandbox_attestation_sha256=launch_plan.sandbox_attestation_sha256,
                    container_id_sha256=agent.container_id_sha256,
                    endpoint_sha256=sha256(endpoint.encode()).hexdigest(),
                    response_sha256=canonical_json_hash(body),
                )
            except Exception as exc:
                last_error = exc
                if attempt + 1 < self._health_attempts and self._health_retry_seconds:
                    time.sleep(self._health_retry_seconds)
        raise RuntimeError("OpenCode runtime did not pass health/version admission") from last_error


def _base_opencode_identity(config: OpenCodeConfig) -> TargetIdentity:
    fingerprint = "|".join(
        [
            config.base_url.rstrip("/"),
            config.model_provider_id,
            config.model_id,
            config.agent,
            config.workspace_root or "",
            config.application_version or "",
            config.session_path,
            config.message_path_template,
            config.persisted_message_path_template,
            str(bool(config.password_env)),
        ]
    )
    return TargetIdentity(
        id=config.id,
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        model=f"{config.model_provider_id}/{config.model_id}",
        provider="opencode",
        runtime=config.base_url,
        application="OpenCode",
        application_version=config.application_version,
        configuration_hash=sha256(fingerprint.encode()).hexdigest(),
        capabilities=config.capabilities,
    )


def _declared_target_identity(
    *,
    opencode_config: OpenCodeConfig,
    runtime_profile: OpenCodeRuntimeProfile,
    sandbox_policy: AgentSandboxPolicy,
) -> TargetIdentity:
    base = _base_opencode_identity(opencode_config)
    transport = DockerExecHttpProfile(
        runtime_profile_sha256=runtime_profile.profile_sha256,
        username=opencode_config.username,
    )
    docker_exec_identity = base.model_copy(
        update={
            "configuration_hash": canonical_json_hash(
                {
                    "base_target_configuration_hash": base.configuration_hash,
                    "control_transport_profile_sha256": transport.profile_sha256,
                }
            ),
            "capabilities": base.capabilities
            | frozenset({"docker_exec_control_transport"}),
        }
    )
    target_policy_sha256 = canonical_json_hash(
        {
            "runtime_profile_sha256": runtime_profile.profile_sha256,
            "sandbox_policy_sha256": sandbox_policy.policy_sha256,
            "workspace_root_sha256": runtime_profile.workspace_root_sha256,
            "mcp_fixture_bridge_sha256": None,
        }
    )
    attested = docker_exec_identity.model_copy(
        update={
            "configuration_hash": canonical_json_hash(
                {
                    "base_target_configuration_hash": docker_exec_identity.configuration_hash,
                    "opencode_target_policy_sha256": target_policy_sha256,
                }
            ),
            "capabilities": docker_exec_identity.capabilities
            | frozenset({"runtime_attested", "runtime_health_verified"}),
        }
    )
    return attested


def _normalized_path(path: Path) -> str:
    value = str(path).replace("\\", "/")
    if len(value) >= 2 and value[1] == ":":
        return value.casefold()
    if value.startswith("//"):
        return value.casefold()
    return value
