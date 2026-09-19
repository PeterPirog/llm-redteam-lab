"""Campaign-scoped Blue infrastructure for the first real HAL AGENT smoke.

The Blue model peer and its isolated Docker network are campaign-scoped infrastructure.
OpenCode AGENT containers and Blue workspaces remain per-trial resources. This supervisor
connects the already-verified primitives without weakening their ownership boundaries:

offline composition -> owned network -> staged Ollama peer -> exact runtime artifact proof
-> disposable OpenCode trial provider.

No model inference is performed while infrastructure is admitted. The Ollama readiness and
artifact probes are explicitly non-inference probes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import Field

from .agent_actions import canonical_json_hash
from .disposable_workspace import DisposableWorkspaceSupervisor
from .docker_model_network_supervisor import (
    DockerModelNetworkLease,
    DockerModelNetworkSupervisor,
)
from .docker_networked_opencode_supervisor import DockerNetworkedOpenCodeSupervisor
from .docker_ollama_artifact import OllamaDockerArtifactProbeProfile
from .docker_ollama_staged_artifact import (
    DockerOllamaStagedArtifactBinding,
    DockerOllamaStagedArtifactVerifier,
)
from .docker_ollama_staged_peer_supervisor import (
    DockerOllamaStagedPeerLease,
    DockerOllamaStagedPeerSupervisor,
)
from .docker_supervisor import DockerCommandRunner
from .domain import StrictModel
from .hal_smoke_preflight import HalSmokeOfflineComposition
from .ollama_artifact import OllamaArtifactContract
from .ollama_model_staging import PreparedOllamaModelStore
from .opencode_trial_isolation import DockerOpenCodeTrialLeaseProvider
from .state_verifiers import StateVerifier

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class HalSmokeBlueInfrastructureLease(StrictModel):
    """Runtime evidence for one campaign-scoped isolated Blue model peer."""

    version: int = Field(ge=1, default=1)
    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    composition_sha256: str = Field(pattern=_HASH_PATTERN)
    target_measurement_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    network: DockerModelNetworkLease
    peer: DockerOllamaStagedPeerLease
    artifact: DockerOllamaStagedArtifactBinding
    probe_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    staged_store_identity_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class HalSmokeBlueInfrastructureRelease(StrictModel):
    """Retry-safe teardown evidence for campaign-scoped Blue infrastructure."""

    version: int = Field(ge=1, default=1)
    lease_id_hash: str = Field(pattern=_HASH_PATTERN)
    peer_released: bool
    network_released: bool
    cleanup_complete: bool
    teardown_proof_sha256: str = Field(pattern=_HASH_PATTERN)


@dataclass(slots=True)
class _ActiveInfrastructure:
    lease: HalSmokeBlueInfrastructureLease
    composition: HalSmokeOfflineComposition
    trial_providers: list[DockerOpenCodeTrialLeaseProvider] = field(default_factory=list)
    peer_released: bool = False
    network_released: bool = False


class HalSmokeBlueInfrastructureSupervisor:
    """Admit and release exact campaign-scoped HAL Blue infrastructure fail closed."""

    def __init__(
        self,
        *,
        network_supervisor: DockerModelNetworkSupervisor,
        peer_supervisor: DockerOllamaStagedPeerSupervisor,
        artifact_verifier: DockerOllamaStagedArtifactVerifier,
    ) -> None:
        self._network_supervisor = network_supervisor
        self._peer_supervisor = peer_supervisor
        self._artifact_verifier = artifact_verifier
        self._active: dict[str, _ActiveInfrastructure] = {}

    def launch(
        self,
        *,
        composition: HalSmokeOfflineComposition,
        staged_store: PreparedOllamaModelStore,
        artifact_contract: OllamaArtifactContract,
        network_name: str,
    ) -> HalSmokeBlueInfrastructureLease:
        """Return only after exact staged bytes are proven in the owned runtime peer."""

        _validate_static_chain(
            composition=composition,
            staged_store=staged_store,
            artifact_contract=artifact_contract,
        )
        if not network_name or any(character.isspace() for character in network_name):
            raise ValueError("HAL smoke network_name must be non-empty and contain no whitespace")

        network: DockerModelNetworkLease | None = None
        peer: DockerOllamaStagedPeerLease | None = None
        try:
            network = self._network_supervisor.create(
                profile=composition.model_network,
                network_name=network_name,
            )
            peer = self._peer_supervisor.launch_staged(
                profile=composition.model_peer,
                staged_store=staged_store,
                network_profile=composition.model_network,
                network_lease=network,
            )
            probe = OllamaDockerArtifactProbeProfile(
                peer_profile_sha256=composition.model_peer.profile_sha256
            )
            artifact = self._artifact_verifier.verify(
                peer_profile=composition.model_peer,
                peer_lease=peer,
                staged_store=staged_store,
                contract=artifact_contract,
                probe_profile=probe,
            )
            _validate_runtime_chain(
                composition=composition,
                network=network,
                peer=peer,
                artifact=artifact,
                staged_store=staged_store,
            )
        except Exception as exc:
            cleanup_complete = self._cleanup_failed_launch(
                peer=peer,
                network=network,
            )
            if not cleanup_complete:
                raise RuntimeError(
                    "HAL Blue infrastructure admission failed and cleanup was incomplete"
                ) from exc
            raise

        lease_id_hash = canonical_json_hash(
            {
                "composition_sha256": composition.composition_sha256,
                "target_measurement_binding_sha256": (
                    composition.target_measurement_binding_sha256
                ),
                "network_id_sha256": network.network_id_sha256,
                "peer_container_id_sha256": peer.peer.container_id_sha256,
                "staged_peer_proof_sha256": peer.proof_sha256,
                "artifact_proof_sha256": artifact.proof_sha256,
            }
        )
        if lease_id_hash in self._active:
            # Exact runtime identities must not be silently adopted/reused.
            cleanup_complete = self._cleanup_failed_launch(peer=peer, network=network)
            if not cleanup_complete:
                raise RuntimeError(
                    "HAL Blue infrastructure identity was reused and cleanup was incomplete"
                )
            raise RuntimeError("HAL Blue infrastructure lease identity was reused")

        lease = HalSmokeBlueInfrastructureLease(
            lease_id_hash=lease_id_hash,
            composition_sha256=composition.composition_sha256,
            target_measurement_binding_sha256=(
                composition.target_measurement_binding_sha256
            ),
            network=network,
            peer=peer,
            artifact=artifact,
            probe_profile_sha256=probe.profile_sha256,
            staged_store_identity_sha256=staged_store.identity.identity_sha256,
        )
        self._active[lease_id_hash] = _ActiveInfrastructure(
            lease=lease,
            composition=composition,
        )
        return lease

    def build_trial_provider(
        self,
        *,
        lease: HalSmokeBlueInfrastructureLease,
        provider_id: str,
        workspace_supervisor: DisposableWorkspaceSupervisor,
        runtime_supervisor: DockerNetworkedOpenCodeSupervisor,
        runner: DockerCommandRunner,
        state_verifier_factory: Callable[[Path], tuple[StateVerifier, ...]] | None = None,
        state_verifier_policy_sha256: str | None = None,
        health_python_executable: str = "python",
    ) -> DockerOpenCodeTrialLeaseProvider:
        """Build per-trial AGENT isolation from the still-active exact Blue peer."""

        active = self._require_active(lease)
        if active.peer_released or active.network_released:
            raise RuntimeError("HAL Blue infrastructure is already partially released")
        composition = active.composition
        provider = DockerOpenCodeTrialLeaseProvider(
            provider_id=provider_id,
            workspace_supervisor=workspace_supervisor,
            runtime_supervisor=runtime_supervisor,
            runner=runner,
            docker_profile=composition.opencode_agent,
            launch_policy=composition.opencode_launch_policy,
            model_network_profile=composition.model_network,
            network_lease=lease.network,
            model_peer_container_id_sha256=lease.peer.peer.container_id_sha256,
            runtime_profile=composition.opencode_runtime,
            sandbox_policy=composition.sandbox_policy,
            opencode_config=composition.target_config,
            target_measurement_binding_sha256=(
                composition.target_measurement_binding_sha256
            ),
            model_peer_runtime_proof_sha256=lease.artifact.proof_sha256,
            state_verifier_factory=state_verifier_factory,
            state_verifier_policy_sha256=state_verifier_policy_sha256,
            health_python_executable=health_python_executable,
        )
        active.trial_providers.append(provider)
        return provider

    def release(
        self,
        lease: HalSmokeBlueInfrastructureLease,
    ) -> HalSmokeBlueInfrastructureRelease:
        """Release the exact model peer first and only then its isolated network."""

        active = self._require_active(lease)
        if any(provider.active_trial_count for provider in active.trial_providers):
            raise RuntimeError(
                "cannot release HAL Blue infrastructure while trial leases are active"
            )

        if not active.peer_released:
            try:
                self._peer_supervisor.release_staged(lease.peer)
            except Exception:
                pass
            else:
                active.peer_released = True

        if active.peer_released and not active.network_released:
            try:
                self._network_supervisor.release(lease.network)
            except Exception:
                pass
            else:
                active.network_released = True

        cleanup_complete = active.peer_released and active.network_released
        teardown_proof_sha256 = canonical_json_hash(
            {
                "lease_id_hash": lease.lease_id_hash,
                "infrastructure_proof_sha256": lease.proof_sha256,
                "peer_released": active.peer_released,
                "network_released": active.network_released,
                "cleanup_complete": cleanup_complete,
            }
        )
        if cleanup_complete:
            del self._active[lease.lease_id_hash]
        return HalSmokeBlueInfrastructureRelease(
            lease_id_hash=lease.lease_id_hash,
            peer_released=active.peer_released,
            network_released=active.network_released,
            cleanup_complete=cleanup_complete,
            teardown_proof_sha256=teardown_proof_sha256,
        )

    def _require_active(
        self,
        lease: HalSmokeBlueInfrastructureLease,
    ) -> _ActiveInfrastructure:
        active = self._active.get(lease.lease_id_hash)
        if active is None:
            raise RuntimeError("HAL Blue infrastructure lease is not active")
        if active.lease != lease:
            raise RuntimeError("HAL Blue infrastructure lease evidence changed")
        return active

    def _cleanup_failed_launch(
        self,
        *,
        peer: DockerOllamaStagedPeerLease | None,
        network: DockerModelNetworkLease | None,
    ) -> bool:
        peer_removed = peer is None
        if peer is not None:
            try:
                self._peer_supervisor.release_staged(peer)
            except Exception:
                peer_removed = False
            else:
                peer_removed = True
        if not peer_removed:
            # Preserve the network while an exact peer may still be attached.
            return False

        network_removed = network is None
        if network is not None:
            try:
                self._network_supervisor.release(network)
            except Exception:
                network_removed = False
            else:
                network_removed = True
        return network_removed


def _validate_static_chain(
    *,
    composition: HalSmokeOfflineComposition,
    staged_store: PreparedOllamaModelStore,
    artifact_contract: OllamaArtifactContract,
) -> None:
    blue_model = composition.static_plan.blue_model_id
    store = staged_store.identity
    peer = composition.model_peer

    if composition.live_runtime_admitted:
        raise ValueError("offline composition cannot claim live runtime admission")
    if peer.provider_id != "ollama":
        raise ValueError("HAL smoke Blue peer must use Ollama")
    if peer.model_id != blue_model:
        raise ValueError("HAL smoke peer model differs from the static Blue model")
    if peer.staged_store_identity_sha256 != store.identity_sha256:
        raise ValueError("HAL smoke peer does not bind the supplied staged store")
    if store.model_id != blue_model:
        raise ValueError("HAL smoke staged store model differs from the Blue model")
    if store.manifest_digest != composition.blue_artifact_digest:
        raise ValueError("HAL smoke staged manifest differs from qualified Blue artifact")
    if not artifact_contract.require_local:
        raise ValueError("HAL smoke requires a local-only Blue artifact contract")
    if artifact_contract.model_id != blue_model:
        raise ValueError("HAL smoke Blue artifact contract names a different model")
    if artifact_contract.manifest_digest != composition.blue_artifact_digest:
        raise ValueError("HAL smoke Blue contract digest differs from offline composition")


def _validate_runtime_chain(
    *,
    composition: HalSmokeOfflineComposition,
    network: DockerModelNetworkLease,
    peer: DockerOllamaStagedPeerLease,
    artifact: DockerOllamaStagedArtifactBinding,
    staged_store: PreparedOllamaModelStore,
) -> None:
    if network.network_profile_sha256 != composition.model_network.profile_sha256:
        raise RuntimeError("runtime network lease does not bind the HAL smoke network profile")
    if peer.peer.network_id_sha256 != network.network_id_sha256:
        raise RuntimeError("runtime model peer is attached to a different network")
    if peer.peer.profile_sha256 != composition.model_peer.profile_sha256:
        raise RuntimeError("runtime model peer does not bind the HAL smoke peer profile")
    if peer.staged_store_identity_sha256 != staged_store.identity.identity_sha256:
        raise RuntimeError("runtime model peer does not bind the staged Blue store")
    if artifact.peer_profile_sha256 != composition.model_peer.profile_sha256:
        raise RuntimeError("runtime artifact proof does not bind the Blue peer profile")
    if artifact.container_id_sha256 != peer.peer.container_id_sha256:
        raise RuntimeError("runtime artifact proof does not bind the Blue peer container")
    if artifact.staged_store_identity_sha256 != staged_store.identity.identity_sha256:
        raise RuntimeError("runtime artifact proof does not bind the staged Blue store")
