"""Disposable per-trial OpenCode AGENT target leases.

This module is deliberately a thin composition layer. Workspace ownership, Docker/network
ownership, running environment attestation and health admission remain implemented and
tested by their dedicated supervisors. The provider only composes those already-trusted
proofs into the generic ``TargetTrialLeaseProvider`` contract used by attacker-pool runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .agent_actions import canonical_json_hash
from .disposable_workspace import (
    DisposableWorkspaceRelease,
    DisposableWorkspaceSupervisor,
    PreparedDisposableWorkspace,
)
from .docker_exec_http import DockerExecContainerRef, DockerExecHttpProfile
from .docker_exec_opencode import build_attested_docker_exec_opencode_target
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_network_supervisor import DockerModelNetworkLease
from .docker_networked_opencode_profile import DockerNetworkedOpenCodeAgentProfile
from .docker_networked_opencode_supervisor import (
    DockerNetworkedOpenCodeLease,
    DockerNetworkedOpenCodeSupervisor,
)
from .docker_supervisor import DockerCommandRunner
from .domain import TargetClass, TargetIdentity, TargetMode
from .opencode_health import HealthGatedOpenCodeTarget
from .opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from .opencode_runtime import AgentSandboxPolicy, OpenCodeRuntimeProfile
from .target_measurement_binding import (
    MeasurementBoundTarget,
    bind_target_measurement_identity,
)
from .target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialIsolationAttestation,
    TargetTrialIsolationRelease,
    TargetTrialLease,
)
from .targets.base import TargetAdapter, TargetRequest, TargetResponse
from .targets.opencode import OpenCodeConfig


class DeclaredIsolatedOpenCodeTarget:
    """Stable planning target that refuses execution outside a disposable trial lease."""

    def __init__(self, identity: TargetIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> TargetIdentity:
        return self._identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        del request
        return TargetResponse(error_kind="isolation:disposable_trial_lease_required")


@dataclass(slots=True)
class _ActiveTrial:
    target: TargetAdapter
    workspace: PreparedDisposableWorkspace
    runtime: DockerNetworkedOpenCodeLease
    runtime_released: bool = False
    target_closed: bool = False
    workspace_released: bool = False
    workspace_release: DisposableWorkspaceRelease | None = None


class DockerOpenCodeTrialLeaseProvider:
    """Issue one fresh workspace + OpenCode container for every AGENT trial."""

    def __init__(
        self,
        *,
        provider_id: str,
        workspace_supervisor: DisposableWorkspaceSupervisor,
        runtime_supervisor: DockerNetworkedOpenCodeSupervisor,
        runner: DockerCommandRunner,
        docker_profile: DockerNetworkedOpenCodeAgentProfile,
        launch_policy: OpenCodeNetworkedLaunchPolicy,
        model_network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
        model_peer_container_id_sha256: str,
        runtime_profile: OpenCodeRuntimeProfile,
        sandbox_policy: AgentSandboxPolicy,
        opencode_config: OpenCodeConfig,
        target_measurement_binding_sha256: str | None = None,
        model_peer_runtime_proof_sha256: str | None = None,
        health_python_executable: str = "python",
    ) -> None:
        if not provider_id:
            raise ValueError("target isolation provider_id must be non-empty")
        if runtime_profile.mcp_fixture_bridge is not None:
            raise ValueError(
                "disposable OpenCode trial leases do not yet support MCP sidecars; "
                "compound fixture/target isolation is required"
            )
        if not sandbox_policy.disposable_workspace:
            raise ValueError("OpenCode trial provider requires disposable_workspace")
        if not sandbox_policy.external_network_denied:
            raise ValueError("OpenCode trial provider requires external network denial")
        if not sandbox_policy.git_publication_denied:
            raise ValueError("OpenCode trial provider requires git publication denial")
        if sandbox_policy.allowed_network_endpoints:
            raise ValueError("OpenCode trial provider requires model-only Docker networking")
        if sandbox_policy.enforcement_profile_sha256 != docker_profile.profile_sha256:
            raise ValueError("sandbox policy does not bind the Docker AGENT profile")
        if docker_profile.launch_policy_sha256 != launch_policy.policy_sha256:
            raise ValueError("Docker AGENT profile does not bind the networked launch policy")
        if docker_profile.model_network_profile_sha256 != model_network_profile.profile_sha256:
            raise ValueError("Docker AGENT profile does not bind the model network")
        if network_lease.network_profile_sha256 != model_network_profile.profile_sha256:
            raise ValueError("model-network lease does not bind the model network")
        if launch_policy.runtime.profile_sha256 != runtime_profile.profile_sha256:
            raise ValueError("networked launch policy does not bind the runtime profile")
        launch_policy.model_binding.validate_network(model_network_profile)
        launch_policy.validate_target_config(opencode_config)
        if opencode_config.application_version is None:
            raise ValueError("disposable OpenCode target requires pinned application_version")
        if not _is_sha256(model_peer_container_id_sha256):
            raise ValueError("model-peer container identity must be a lowercase SHA-256")
        if target_measurement_binding_sha256 is not None and not _is_sha256(
            target_measurement_binding_sha256
        ):
            raise ValueError("target measurement binding must be a lowercase SHA-256")
        if model_peer_runtime_proof_sha256 is not None and not _is_sha256(
            model_peer_runtime_proof_sha256
        ):
            raise ValueError("model-peer runtime proof must be a lowercase SHA-256")
        if not health_python_executable or any(
            character.isspace() for character in health_python_executable
        ):
            raise ValueError("health_python_executable must be one executable token")

        self._workspace_supervisor = workspace_supervisor
        self._runtime_supervisor = runtime_supervisor
        self._runner = runner
        self.docker_profile = docker_profile
        self.launch_policy = launch_policy
        self.model_network_profile = model_network_profile
        self.network_lease = network_lease
        self.model_peer_container_id_sha256 = model_peer_container_id_sha256
        self.runtime_profile = runtime_profile
        self.sandbox_policy = sandbox_policy
        self.opencode_config = opencode_config
        self.target_measurement_binding_sha256 = target_measurement_binding_sha256
        self.model_peer_runtime_proof_sha256 = model_peer_runtime_proof_sha256
        self.health_python_executable = health_python_executable
        self._counter = 0
        self._active: dict[str, _ActiveTrial] = {}

        self._declared_identity = _declared_identity(
            config=opencode_config,
            runtime_profile=runtime_profile,
            sandbox_policy=sandbox_policy,
            launch_policy=launch_policy,
            measurement_binding_sha256=target_measurement_binding_sha256,
        )
        self._declared_target = DeclaredIsolatedOpenCodeTarget(self._declared_identity)
        self._provider_fingerprint = canonical_json_hash(
            {
                "kind": "docker-networked-opencode-trial-lease-v2",
                "provider_id": provider_id,
                "workspace_profile_sha256": workspace_supervisor.profile.profile_sha256,
                "docker_profile_sha256": docker_profile.profile_sha256,
                "launch_policy_sha256": launch_policy.policy_sha256,
                "model_network_profile_sha256": model_network_profile.profile_sha256,
                "runtime_profile_sha256": runtime_profile.profile_sha256,
                "sandbox_policy_sha256": sandbox_policy.policy_sha256,
                "declared_target_configuration_hash": self._declared_identity.configuration_hash,
                "target_measurement_binding_sha256": target_measurement_binding_sha256,
                "health_python_executable": health_python_executable,
            }
        )

    @property
    def provider_fingerprint(self) -> str:
        return self._provider_fingerprint

    @property
    def isolation_level(self) -> TargetIsolationLevel:
        return TargetIsolationLevel.DISPOSABLE_SANDBOX

    @property
    def declared_target(self) -> TargetAdapter:
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

        workspace = self._workspace_supervisor.prepare(trial_id=trial_id)
        runtime: DockerNetworkedOpenCodeLease | None = None
        target: TargetAdapter | None = None
        try:
            self._counter += 1
            container_name = "llmrt-agent-" + canonical_json_hash(
                {
                    "provider_fingerprint": self._provider_fingerprint,
                    "trial_id_sha256": sha256(trial_id.encode()).hexdigest(),
                    "ordinal": self._counter,
                }
            )[:24]
            runtime = self._runtime_supervisor.launch(
                profile=self.docker_profile,
                launch_policy=self.launch_policy,
                model_network_profile=self.model_network_profile,
                network_lease=self.network_lease,
                model_peer_container_id_sha256=self.model_peer_container_id_sha256,
                runtime_profile=self.runtime_profile,
                sandbox_policy=self.sandbox_policy,
                workspace_host_path=str(workspace.path),
                container_name=container_name,
                health_python_executable=self.health_python_executable,
            )
            container = DockerExecContainerRef(
                container_name=runtime.agent.container_name,
                container_id_sha256=runtime.agent.container_id_sha256,
            )
            attested = build_attested_docker_exec_opencode_target(
                config=self.opencode_config,
                runtime_profile=self.runtime_profile,
                launch_plan=runtime.launch_plan,
                container=container,
                runner=self._runner,
            )
            target = HealthGatedOpenCodeTarget(attested, runtime.health)
            if self.target_measurement_binding_sha256 is not None:
                target = MeasurementBoundTarget(
                    target,
                    measurement_binding_sha256=self.target_measurement_binding_sha256,
                )
            if target.identity != expected_identity:
                raise ValueError("constructed disposable OpenCode target differs from declaration")

            fresh_state_proof_hash = canonical_json_hash(
                {
                    "workspace_lease_id_hash": workspace.lease.lease_id_hash,
                    "workspace_profile_sha256": workspace.lease.profile_sha256,
                    "workspace_initial_tree_sha256": workspace.lease.initial_tree_sha256,
                    "runtime_proof_sha256": runtime.proof_sha256,
                    "model_peer_container_id_sha256": self.model_peer_container_id_sha256,
                    "target_measurement_binding_sha256": (
                        self.target_measurement_binding_sha256
                    ),
                    "model_peer_runtime_proof_sha256": (
                        self.model_peer_runtime_proof_sha256
                    ),
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
            self._active[lease_id_hash] = _ActiveTrial(
                target=target,
                workspace=workspace,
                runtime=runtime,
            )
            return TargetTrialLease(
                target=target,
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
            cleanup_complete = self._cleanup_failed_acquisition(
                target=target,
                runtime=runtime,
                workspace=workspace,
            )
            if not cleanup_complete:
                raise RuntimeError(
                    "OpenCode trial acquisition failed and cleanup was incomplete"
                ) from exc
            raise

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        """Synchronous compatibility path; requires no async target close."""

        return self._release_resources(lease, target_closed=False)

    async def release_async(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        """Close transport first, then remove the exact container and workspace."""

        active = self._require_active(lease)
        if not active.target_closed:
            close = getattr(active.target, "aclose", None)
            if close is not None:
                await close()
            active.target_closed = True
        return self._release_resources(lease, target_closed=True)

    def _release_resources(
        self,
        lease: TargetTrialLease,
        *,
        target_closed: bool,
    ) -> TargetTrialIsolationRelease:
        active = self._require_active(lease)
        if target_closed:
            active.target_closed = True

        if not active.runtime_released:
            try:
                self._runtime_supervisor.release(active.runtime)
            except Exception:
                pass
            else:
                active.runtime_released = True

        if active.runtime_released and not active.workspace_released:
            try:
                release = self._workspace_supervisor.release(active.workspace)
            except Exception:
                release = None
            if release is not None:
                active.workspace_release = release
                active.workspace_released = release.cleanup_complete

        cleanup_complete = active.runtime_released and active.workspace_released
        teardown_proof_hash = canonical_json_hash(
            {
                "lease_id_hash": lease.attestation.lease_id_hash,
                "provider_fingerprint": self._provider_fingerprint,
                "target_closed": active.target_closed,
                "runtime_proof_sha256": active.runtime.proof_sha256,
                "runtime_released": active.runtime_released,
                "workspace_lease_id_hash": active.workspace.lease.lease_id_hash,
                "workspace_teardown_proof_sha256": (
                    active.workspace_release.teardown_proof_sha256
                    if active.workspace_release is not None
                    else None
                ),
                "workspace_released": active.workspace_released,
                "cleanup_complete": cleanup_complete,
            }
        )
        if cleanup_complete:
            del self._active[lease.attestation.lease_id_hash]
        return TargetTrialIsolationRelease(
            lease_id_hash=lease.attestation.lease_id_hash,
            teardown_proof_hash=teardown_proof_hash,
            cleanup_complete=cleanup_complete,
        )

    def _require_active(self, lease: TargetTrialLease) -> _ActiveTrial:
        active = self._active.get(lease.attestation.lease_id_hash)
        if active is None:
            raise RuntimeError("target isolation lease is not active")
        if active.target is not lease.target:
            raise RuntimeError("target isolation lease target changed")
        return active

    def _cleanup_failed_acquisition(
        self,
        *,
        target: TargetAdapter | None,
        runtime: DockerNetworkedOpenCodeLease | None,
        workspace: PreparedDisposableWorkspace,
    ) -> bool:
        # Acquisition is synchronous, so an AsyncClient created immediately before a
        # subsequent identity failure cannot be awaited here. Runtime containment is the
        # security boundary: remove it first, then the workspace. The async client owns no
        # published host socket and becomes unreachable with the container.
        del target
        runtime_removed = runtime is None
        if runtime is not None:
            try:
                self._runtime_supervisor.release(runtime)
            except Exception:
                runtime_removed = False
            else:
                runtime_removed = True
        if not runtime_removed:
            return False
        try:
            workspace_release = self._workspace_supervisor.release(workspace)
        except Exception:
            return False
        return workspace_release.cleanup_complete


def _declared_identity(
    *,
    config: OpenCodeConfig,
    runtime_profile: OpenCodeRuntimeProfile,
    sandbox_policy: AgentSandboxPolicy,
    launch_policy: OpenCodeNetworkedLaunchPolicy,
    measurement_binding_sha256: str | None = None,
) -> TargetIdentity:
    """Reproduce stable runtime target identity without creating a live HTTP client."""

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
    base = TargetIdentity(
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
    transport = DockerExecHttpProfile(
        runtime_profile_sha256=runtime_profile.profile_sha256,
        username=config.username,
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
    base_target_policy_sha256 = canonical_json_hash(
        {
            "runtime_profile_sha256": runtime_profile.profile_sha256,
            "sandbox_policy_sha256": sandbox_policy.policy_sha256,
            "workspace_root_sha256": runtime_profile.workspace_root_sha256,
            "mcp_fixture_bridge_sha256": None,
        }
    )
    networked_target_policy_sha256 = canonical_json_hash(
        {
            "base_target_policy_sha256": base_target_policy_sha256,
            "model_binding_sha256": launch_policy.model_binding.binding_sha256,
            "networked_launch_policy_sha256": launch_policy.policy_sha256,
        }
    )
    identity = docker_exec_identity.model_copy(
        update={
            "configuration_hash": canonical_json_hash(
                {
                    "base_target_configuration_hash": (
                        docker_exec_identity.configuration_hash
                    ),
                    "opencode_target_policy_sha256": networked_target_policy_sha256,
                }
            ),
            "capabilities": docker_exec_identity.capabilities
            | frozenset({"runtime_attested", "runtime_health_verified"}),
        }
    )
    if measurement_binding_sha256 is None:
        return identity
    return bind_target_measurement_identity(
        identity,
        measurement_binding_sha256=measurement_binding_sha256,
    )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
