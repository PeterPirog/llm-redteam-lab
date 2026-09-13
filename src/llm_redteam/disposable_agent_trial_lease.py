"""Transactional per-trial disposable AGENT lease composition.

The provider composes existing trusted supervisors; it does not reimplement Docker,
model-artifact, network, sandbox or OpenCode health attestation. Acquisition is fail-closed
and rollback is attempted in strict reverse order. The first implementation intentionally
permits only one active lease because the trusted model-network profile uses one fixed
model-peer container name.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_network_supervisor import (
    DockerModelNetworkLease,
    DockerModelNetworkSupervisor,
)
from .docker_model_peer import DockerModelPeerProfile
from .docker_networked_sandbox import DockerNetworkedAgentProfile
from .docker_networked_supervisor import (
    DockerNetworkedAgentLease,
    DockerNetworkedAgentSupervisor,
)
from .domain import StrictModel, TargetIdentity, TargetMode
from .ollama_artifact_bundle import OllamaArtifactBundleContract
from .ollama_model_peer import OllamaModelPeerProfile
from .ollama_model_peer_supervisor import (
    OllamaModelPeerLease,
    OllamaModelPeerRelease,
    OllamaModelPeerSupervisor,
)
from .opencode_health import OpenCodeHealthObservation
from .opencode_runtime import AgentSandboxPolicy, OpenCodeRuntimeProfile
from .target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialIsolationAttestation,
    TargetTrialIsolationRelease,
    TargetTrialLease,
)
from .targets.base import TargetAdapter

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DisposableAgentWorkspaceLease(StrictModel):
    """Trusted fresh disposable workspace allocated for exactly one trial."""

    host_path: str = Field(min_length=1)
    workspace_id_sha256: str = Field(pattern=_HASH_PATTERN)
    fresh_state_proof_sha256: str = Field(pattern=_HASH_PATTERN)


class DisposableAgentWorkspaceRelease(StrictModel):
    """Hash-only evidence that a disposable workspace was removed or reset."""

    workspace_id_sha256: str = Field(pattern=_HASH_PATTERN)
    teardown_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool


class DisposableAgentWorkspaceProvider(Protocol):
    """Trusted workspace allocator; fixture seeding remains outside this orchestrator."""

    @property
    def provider_fingerprint(self) -> str: ...

    def acquire(self, *, trial_id: str) -> DisposableAgentWorkspaceLease: ...

    def release(
        self,
        lease: DisposableAgentWorkspaceLease,
    ) -> DisposableAgentWorkspaceRelease: ...


class DisposableAgentTargetRelease(StrictModel):
    """Hash-only target/transport cleanup evidence."""

    teardown_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class DisposableAgentTargetHandle:
    """Health-gated target produced for the exact launched AGENT container."""

    target: TargetAdapter
    health: OpenCodeHealthObservation


class DisposableAgentTargetFactory(Protocol):
    """Trusted OpenCode target/health boundary injected by runtime integration."""

    @property
    def provider_fingerprint(self) -> str: ...

    def build(
        self,
        *,
        agent_lease: DockerNetworkedAgentLease,
        expected_identity: TargetIdentity,
    ) -> DisposableAgentTargetHandle: ...

    def release(self, handle: DisposableAgentTargetHandle) -> DisposableAgentTargetRelease: ...


@dataclass(slots=True)
class _ActiveTrial:
    workspace: DisposableAgentWorkspaceLease
    network: DockerModelNetworkLease
    model_peer: OllamaModelPeerLease
    agent: DockerNetworkedAgentLease
    target_handle: DisposableAgentTargetHandle
    expected_identity: TargetIdentity
    public_lease: TargetTrialLease


class DisposableAgentTrialLeaseProvider:
    """Compose one exact model peer and one disposable OpenCode AGENT per trial.

    The provider owns orchestration only. Each component supervisor remains authoritative for
    its own admission, ownership checks and teardown. A failed cleanup permanently marks this
    provider instance dirty so it cannot silently launch another trial over uncertain state.
    """

    _VERSION = 1

    def __init__(
        self,
        *,
        workspace_provider: DisposableAgentWorkspaceProvider,
        network_supervisor: DockerModelNetworkSupervisor,
        network_profile: DockerIsolatedModelNetworkProfile,
        model_peer_supervisor: OllamaModelPeerSupervisor,
        ollama_profile: OllamaModelPeerProfile,
        model_peer_profile: DockerModelPeerProfile,
        bundle_contract: OllamaArtifactBundleContract,
        bundle_host_path: Path,
        agent_supervisor: DockerNetworkedAgentSupervisor,
        agent_profile: DockerNetworkedAgentProfile,
        runtime_profile: OpenCodeRuntimeProfile,
        sandbox_policy: AgentSandboxPolicy,
        agent_command: tuple[str, ...],
        target_factory: DisposableAgentTargetFactory,
    ) -> None:
        if not agent_command:
            raise ValueError("disposable AGENT command must be non-empty")
        self._workspace_provider = workspace_provider
        self._network_supervisor = network_supervisor
        self._network_profile = network_profile
        self._model_peer_supervisor = model_peer_supervisor
        self._ollama_profile = ollama_profile
        self._model_peer_profile = model_peer_profile
        self._bundle_contract = bundle_contract
        self._bundle_host_path = bundle_host_path
        self._agent_supervisor = agent_supervisor
        self._agent_profile = agent_profile
        self._runtime_profile = runtime_profile
        self._sandbox_policy = sandbox_policy
        self._agent_command = agent_command
        self._target_factory = target_factory
        self._active: dict[str, _ActiveTrial] = {}
        self._seen_lease_ids: set[str] = set()
        self._seen_workspace_ids: set[str] = set()
        self._seen_fresh_state_proofs: set[str] = set()
        self._dirty = False

        # Fail fast on stable policy contradictions; detailed runtime ownership remains in
        # the component supervisors.
        if network_profile.profile_sha256 != agent_profile.model_network_profile_sha256:
            raise ValueError("AGENT profile does not bind the supplied model-network profile")
        if model_peer_profile.profile_sha256 != ollama_profile.peer_profile_sha256:
            raise ValueError("Ollama profile does not bind the supplied model-peer profile")
        if bundle_contract.bundle_sha256 != ollama_profile.bundle_contract_sha256:
            raise ValueError("Ollama profile does not bind the supplied artifact bundle")
        if sandbox_policy.enforcement_profile_sha256 != agent_profile.profile_sha256:
            raise ValueError("sandbox policy does not bind the supplied AGENT profile")

    @property
    def isolation_level(self) -> TargetIsolationLevel:
        return TargetIsolationLevel.DISPOSABLE_SANDBOX

    @property
    def provider_fingerprint(self) -> str:
        return canonical_json_hash(
            {
                "kind": "disposable-agent-trial-lease",
                "version": self._VERSION,
                "workspace_provider_fingerprint": self._workspace_provider.provider_fingerprint,
                "network_profile_sha256": self._network_profile.profile_sha256,
                "ollama_profile_sha256": self._ollama_profile.profile_sha256,
                "model_peer_profile_sha256": self._model_peer_profile.profile_sha256,
                "bundle_contract_sha256": self._bundle_contract.bundle_sha256,
                "agent_profile_sha256": self._agent_profile.profile_sha256,
                "runtime_profile_sha256": self._runtime_profile.profile_sha256,
                "sandbox_policy_sha256": self._sandbox_policy.policy_sha256,
                "agent_command_sha256": canonical_json_hash(list(self._agent_command)),
                "target_factory_fingerprint": self._target_factory.provider_fingerprint,
                "concurrency": "single-active-lease-v1",
            }
        )

    def acquire(
        self,
        *,
        expected_identity: TargetIdentity,
        trial_id: str,
    ) -> TargetTrialLease:
        """Allocate all per-trial resources and return only after exact health admission."""

        if self._dirty:
            raise RuntimeError("disposable AGENT lease provider is dirty after cleanup failure")
        if self._active:
            raise RuntimeError("concurrent disposable AGENT trial leases are not supported")
        if expected_identity.target_mode != TargetMode.AGENT:
            raise ValueError("disposable AGENT lease requires target_mode=AGENT")
        if not trial_id:
            raise ValueError("trial_id must be non-empty")

        lease_id_hash = canonical_json_hash(
            {
                "provider_fingerprint": self.provider_fingerprint,
                "trial_id": trial_id,
                "target_id": expected_identity.id,
                "target_configuration_hash": expected_identity.configuration_hash,
            }
        )
        if lease_id_hash in self._seen_lease_ids:
            raise ValueError("disposable AGENT trial lease identity was already used")
        self._seen_lease_ids.add(lease_id_hash)

        suffix = lease_id_hash[:20]
        network_name = f"llmrt-net-{suffix}"
        agent_container_name = f"llmrt-agent-{suffix}"

        workspace: DisposableAgentWorkspaceLease | None = None
        network: DockerModelNetworkLease | None = None
        model_peer: OllamaModelPeerLease | None = None
        agent: DockerNetworkedAgentLease | None = None
        target_handle: DisposableAgentTargetHandle | None = None
        try:
            workspace = self._workspace_provider.acquire(trial_id=trial_id)
            self._admit_fresh_workspace(workspace)
            network = self._network_supervisor.create(
                profile=self._network_profile,
                network_name=network_name,
            )
            model_peer = self._model_peer_supervisor.launch(
                profile=self._ollama_profile,
                peer=self._model_peer_profile,
                bundle_contract=self._bundle_contract,
                bundle_host_path=self._bundle_host_path,
                network_profile=self._network_profile,
                network_lease=network,
            )
            agent = self._agent_supervisor.launch(
                docker_profile=self._agent_profile,
                model_network_profile=self._network_profile,
                network_lease=network,
                model_peer_container_id_sha256=model_peer.container_id_sha256,
                runtime_profile=self._runtime_profile,
                sandbox_policy=self._sandbox_policy,
                workspace_host_path=workspace.host_path,
                container_name=agent_container_name,
                command=self._agent_command,
            )
            target_handle = self._target_factory.build(
                agent_lease=agent,
                expected_identity=expected_identity,
            )
            self._validate_target_handle(
                handle=target_handle,
                agent=agent,
                expected_identity=expected_identity,
            )

            attestation = TargetTrialIsolationAttestation(
                lease_id_hash=lease_id_hash,
                provider_fingerprint=self.provider_fingerprint,
                isolation_level=self.isolation_level,
                target_configuration_hash=expected_identity.configuration_hash,
                fresh_state_proof_hash=canonical_json_hash(
                    {
                        "lease_id_hash": lease_id_hash,
                        "workspace_id_sha256": workspace.workspace_id_sha256,
                        "workspace_fresh_state_proof_sha256": (
                            workspace.fresh_state_proof_sha256
                        ),
                        "network_id_sha256": network.network_id_sha256,
                        "network_create_command_sha256": network.create_command_sha256,
                        "model_peer_container_id_sha256": model_peer.container_id_sha256,
                        "model_peer_launch_command_sha256": model_peer.launch_command_sha256,
                        "model_peer_bundle_contract_sha256": (
                            model_peer.bundle_contract_sha256
                        ),
                        "model_peer_prelaunch_bundle_proof_sha256": (
                            model_peer.prelaunch_bundle_proof_sha256
                        ),
                        "agent_container_id_sha256": agent.container_id_sha256,
                        "agent_launch_command_sha256": agent.launch_command_sha256,
                        "sandbox_attestation_sha256": (
                            agent.sandbox_attestation.attestation_sha256
                        ),
                        "network_attestation_sha256": (
                            agent.network_attestation.attestation_sha256
                        ),
                        "runtime_health_proof_sha256": target_handle.health.proof_sha256,
                    }
                ),
                control_plane_independent=True,
            )
            public_lease = TargetTrialLease(target=target_handle.target, attestation=attestation)
            self._active[lease_id_hash] = _ActiveTrial(
                workspace=workspace,
                network=network,
                model_peer=model_peer,
                agent=agent,
                target_handle=target_handle,
                expected_identity=expected_identity,
                public_lease=public_lease,
            )
            return public_lease
        except Exception as exc:
            cleanup_errors = self._rollback_partial(
                target_handle=target_handle,
                agent=agent,
                model_peer=model_peer,
                network=network,
                workspace=workspace,
            )
            if cleanup_errors:
                self._dirty = True
                raise RuntimeError(
                    "disposable AGENT trial acquisition failed and rollback was incomplete: "
                    + "; ".join(cleanup_errors)
                ) from exc
            raise

    def release(self, lease: TargetTrialLease) -> TargetTrialIsolationRelease:
        """Release every owned component in reverse order, attempting all cleanup steps."""

        lease_id_hash = lease.attestation.lease_id_hash
        active = self._active.get(lease_id_hash)
        if active is None:
            raise ValueError("unknown or already released disposable AGENT trial lease")
        if active.public_lease.attestation != lease.attestation:
            raise ValueError("disposable AGENT trial lease attestation does not match active lease")
        if active.public_lease.target is not lease.target:
            raise ValueError("disposable AGENT trial lease target does not match active lease")

        target_release: DisposableAgentTargetRelease | None = None
        model_release: OllamaModelPeerRelease | None = None
        workspace_release: DisposableAgentWorkspaceRelease | None = None
        cleanup_errors: list[str] = []
        try:
            if lease.target.identity != active.expected_identity:
                cleanup_errors.append("target identity drift detected before release")
        except Exception as exc:
            cleanup_errors.append(f"target identity check failed: {type(exc).__name__}")

        try:
            target_release = self._target_factory.release(active.target_handle)
            if not target_release.cleanup_complete:
                cleanup_errors.append("target cleanup incomplete")
        except Exception as exc:  # cleanup must continue through independent layers
            cleanup_errors.append(f"target cleanup failed: {type(exc).__name__}")

        try:
            self._agent_supervisor.release(active.agent)
        except Exception as exc:
            cleanup_errors.append(f"agent cleanup failed: {type(exc).__name__}")

        try:
            model_release = self._model_peer_supervisor.release(
                lease=active.model_peer,
                bundle_contract=self._bundle_contract,
                bundle_host_path=self._bundle_host_path,
            )
            if not model_release.cleanup_complete:
                cleanup_errors.append("model-peer cleanup incomplete")
            if not model_release.artifact_contract_matched:
                cleanup_errors.append("model-peer artifact contract changed before release")
            if not model_release.artifact_stable:
                cleanup_errors.append("model-peer artifact drift detected before release")
        except Exception as exc:
            cleanup_errors.append(f"model-peer cleanup failed: {type(exc).__name__}")

        try:
            self._network_supervisor.release(active.network)
        except Exception as exc:
            cleanup_errors.append(f"network cleanup failed: {type(exc).__name__}")

        try:
            workspace_release = self._workspace_provider.release(active.workspace)
            if not workspace_release.cleanup_complete:
                cleanup_errors.append("workspace cleanup incomplete")
        except Exception as exc:
            cleanup_errors.append(f"workspace cleanup failed: {type(exc).__name__}")

        if cleanup_errors:
            self._dirty = True
            raise RuntimeError(
                "disposable AGENT trial release failed closed after cleanup attempts: "
                + "; ".join(cleanup_errors)
            )

        assert target_release is not None
        assert model_release is not None
        assert workspace_release is not None
        del self._active[lease_id_hash]
        teardown_proof_hash = canonical_json_hash(
            {
                "lease_id_hash": lease_id_hash,
                "target_teardown_proof_sha256": target_release.teardown_proof_sha256,
                "agent_container_id_sha256": active.agent.container_id_sha256,
                "model_peer_release_proof_sha256": model_release.proof_sha256,
                "network_id_sha256": active.network.network_id_sha256,
                "workspace_teardown_proof_sha256": workspace_release.teardown_proof_sha256,
            }
        )
        return TargetTrialIsolationRelease(
            lease_id_hash=lease_id_hash,
            teardown_proof_hash=teardown_proof_hash,
            cleanup_complete=True,
        )

    def _admit_fresh_workspace(self, workspace: DisposableAgentWorkspaceLease) -> None:
        if workspace.workspace_id_sha256 in self._seen_workspace_ids:
            raise RuntimeError("disposable workspace identity was reused across trials")
        if workspace.fresh_state_proof_sha256 in self._seen_fresh_state_proofs:
            raise RuntimeError("disposable workspace fresh-state proof was reused across trials")
        self._seen_workspace_ids.add(workspace.workspace_id_sha256)
        self._seen_fresh_state_proofs.add(workspace.fresh_state_proof_sha256)

    def _validate_target_handle(
        self,
        *,
        handle: DisposableAgentTargetHandle,
        agent: DockerNetworkedAgentLease,
        expected_identity: TargetIdentity,
    ) -> None:
        if handle.target.identity != expected_identity:
            raise ValueError("health-gated AGENT target identity does not match expected target")
        health = handle.health
        if not health.healthy:
            raise ValueError("OpenCode health observation is unhealthy")
        if health.container_id_sha256 != agent.container_id_sha256:
            raise ValueError("OpenCode health does not bind the launched AGENT container")
        if health.runtime_profile_sha256 != self._runtime_profile.profile_sha256:
            raise ValueError("OpenCode health does not bind the configured runtime profile")
        if (
            health.sandbox_attestation_sha256
            != agent.sandbox_attestation.attestation_sha256
        ):
            raise ValueError("OpenCode health does not bind the AGENT sandbox attestation")
        if expected_identity.application_version is None:
            raise ValueError("disposable OpenCode AGENT target requires application_version")
        if health.application_version != expected_identity.application_version:
            raise ValueError("OpenCode health version does not match expected target version")
        if "runtime_health_verified" not in handle.target.identity.capabilities:
            raise ValueError("AGENT target is missing runtime health verification capability")

    def _rollback_partial(
        self,
        *,
        target_handle: DisposableAgentTargetHandle | None,
        agent: DockerNetworkedAgentLease | None,
        model_peer: OllamaModelPeerLease | None,
        network: DockerModelNetworkLease | None,
        workspace: DisposableAgentWorkspaceLease | None,
    ) -> list[str]:
        errors: list[str] = []
        if target_handle is not None:
            try:
                release = self._target_factory.release(target_handle)
                if not release.cleanup_complete:
                    errors.append("target rollback incomplete")
            except Exception as exc:
                errors.append(f"target rollback failed: {type(exc).__name__}")
        if agent is not None:
            try:
                self._agent_supervisor.release(agent)
            except Exception as exc:
                errors.append(f"agent rollback failed: {type(exc).__name__}")
        if model_peer is not None:
            try:
                release = self._model_peer_supervisor.release(
                    lease=model_peer,
                    bundle_contract=self._bundle_contract,
                    bundle_host_path=self._bundle_host_path,
                )
                if not release.cleanup_complete:
                    errors.append("model-peer rollback incomplete")
                if not release.artifact_contract_matched or not release.artifact_stable:
                    errors.append("model-peer artifact drift detected during rollback")
            except Exception as exc:
                errors.append(f"model-peer rollback failed: {type(exc).__name__}")
        if network is not None:
            try:
                self._network_supervisor.release(network)
            except Exception as exc:
                errors.append(f"network rollback failed: {type(exc).__name__}")
        if workspace is not None:
            try:
                release = self._workspace_provider.release(workspace)
                if not release.cleanup_complete:
                    errors.append("workspace rollback incomplete")
            except Exception as exc:
                errors.append(f"workspace rollback failed: {type(exc).__name__}")
        return errors
