from pathlib import Path
from types import SimpleNamespace

import pytest

from llm_redteam.disposable_workspace import DisposableWorkspaceSupervisor
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_model_peer import (
    DockerModelPeerLease,
    DockerModelPeerReadinessObservation,
)
from llm_redteam.docker_ollama_staged_artifact import (
    DockerOllamaStagedArtifactBinding,
)
from llm_redteam.docker_ollama_staged_peer import DockerOllamaStagedPeerAttestation
from llm_redteam.docker_ollama_staged_peer_supervisor import DockerOllamaStagedPeerLease
from llm_redteam.hal_smoke_preflight import (
    HalSmokeRuntimePins,
    build_hal_smoke_static_plan,
    compose_hal_smoke_offline,
)
from llm_redteam.hal_smoke_runtime import HalSmokeBlueInfrastructureSupervisor
from llm_redteam.model_inventory import (
    LocalModelAdmissionBinding,
    LocalOnlyAdmissionReport,
)
from llm_redteam.model_roles import load_models_config
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.ollama_model_staging import (
    OllamaStagedModelStoreIdentity,
    PreparedOllamaModelStore,
)
from llm_redteam.reference_artifact_qualification import (
    QualifiedArtifactBinding,
    ReferenceArtifactQualificationReport,
)

_BLUE = "ornith-1.5:9b"
_BLUE_DIGEST = "a" * 64
_CONTAINER_ID = "b" * 64


def _composition():
    models = load_models_config("config/models.hal-smoke.example.yaml")
    static = build_hal_smoke_static_plan(models=models, blue_model_id=_BLUE)
    admission = LocalOnlyAdmissionReport(
        inventory_sha256="1" * 64,
        blue_model_id=_BLUE,
        bindings=(
            LocalModelAdmissionBinding(
                label="red_planner",
                model_id=static.red_planner_model_id,
                inventory_record_sha256="2" * 64,
                endpoint_sha256=static.red_planner_endpoint_sha256,
            ),
            LocalModelAdmissionBinding(
                label="red_mutator",
                model_id=static.red_mutator_model_id,
                inventory_record_sha256="3" * 64,
                endpoint_sha256=static.red_mutator_endpoint_sha256,
            ),
            LocalModelAdmissionBinding(
                label="blue",
                model_id=_BLUE,
                inventory_record_sha256="4" * 64,
                endpoint_sha256="5" * 64,
            ),
        ),
    )
    digests = {
        static.red_planner_model_id: "6" * 64,
        static.red_mutator_model_id: "7" * 64,
        _BLUE: _BLUE_DIGEST,
    }
    qualification = ReferenceArtifactQualificationReport(
        local_admission_proof_sha256=admission.proof_sha256,
        contract_set_sha256="8" * 64,
        tags_snapshot_sha256="9" * 64,
        bindings=tuple(
            QualifiedArtifactBinding(
                model_id=model_id,
                contract_sha256="c" * 64,
                artifact_identity_sha256="d" * 64,
                artifact_observation_sha256="e" * 64,
                artifact_digest="sha256:" + digest,
            )
            for model_id, digest in sorted(digests.items())
        ),
    )
    store_identity = OllamaStagedModelStoreIdentity(
        model_id=_BLUE,
        manifest_digest="sha256:" + _BLUE_DIGEST,
        manifest_relative_path_sha256="f" * 64,
        staged_tree_sha256="0" * 64,
        referenced_blob_count=3,
        referenced_blob_bytes=4096,
    )
    pins = HalSmokeRuntimePins(
        staged_blue_store_identity=store_identity,
        opencode_application_version="1.2.3-test",
        opencode_image_ref="synthetic/opencode@sha256:" + "1" * 64,
        opencode_image_id="sha256:" + "2" * 64,
        ollama_peer_image_ref="synthetic/ollama-probe@sha256:" + "3" * 64,
        ollama_peer_image_id="sha256:" + "4" * 64,
    )
    composition = compose_hal_smoke_offline(
        static_plan=static,
        admission=admission,
        qualification=qualification,
        pins=pins,
    )
    return composition, store_identity


def _store(tmp_path: Path, identity: OllamaStagedModelStoreIdentity):
    models_path = tmp_path / "models"
    models_path.mkdir(parents=True)
    return PreparedOllamaModelStore(models_path=models_path, identity=identity)


def _contract():
    return OllamaArtifactContract(
        model_id=_BLUE,
        expected_manifest_digest="sha256:" + _BLUE_DIGEST,
        require_local=True,
    )


class FakeNetworkSupervisor:
    def __init__(self) -> None:
        self.created: list[tuple[object, str]] = []
        self.released: list[DockerModelNetworkLease] = []
        self.fail_release = False

    def create(self, *, profile, network_name):
        self.created.append((profile, network_name))
        return DockerModelNetworkLease(
            network_name=network_name,
            network_id_sha256="a" * 64,
            network_profile_sha256=profile.profile_sha256,
            create_command_sha256="b" * 64,
            engine=DockerEngineVersionObservation(
                server_version="28.0.0",
                major=28,
                minor=0,
                patch=0,
                command_sha256="c" * 64,
            ),
        )

    def release(self, lease):
        if self.fail_release:
            raise RuntimeError("synthetic network release failure")
        self.released.append(lease)


class FakePeerSupervisor:
    def __init__(self) -> None:
        self.launched: list[dict[str, object]] = []
        self.released: list[DockerOllamaStagedPeerLease] = []
        self.fail_release = False

    def launch_staged(self, **kwargs):
        self.launched.append(kwargs)
        profile = kwargs["profile"]
        network_lease = kwargs["network_lease"]
        staged_store = kwargs["staged_store"]
        readiness = DockerModelPeerReadinessObservation(
            provider_id="ollama",
            model_id=profile.model_id,
            profile_sha256=profile.profile_sha256,
            container_id_sha256=_CONTAINER_ID,
            response_sha256="d" * 64,
            ready=True,
        )
        peer = DockerModelPeerLease(
            container_name=kwargs["network_profile"].model_endpoint_host,
            container_id_sha256=_CONTAINER_ID,
            profile_sha256=profile.profile_sha256,
            network_id_sha256=network_lease.network_id_sha256,
            launch_command_sha256="e" * 64,
            readiness=readiness,
        )
        staging = DockerOllamaStagedPeerAttestation(
            peer_profile_sha256=profile.profile_sha256,
            staged_store_identity_sha256=staged_store.identity.identity_sha256,
            container_id_sha256=_CONTAINER_ID,
            mount_source_sha256="f" * 64,
            inspection_sha256="0" * 64,
        )
        return DockerOllamaStagedPeerLease(
            peer=peer,
            staging=staging,
            staged_store_identity_sha256=staged_store.identity.identity_sha256,
        )

    def release_staged(self, lease):
        if self.fail_release:
            raise RuntimeError("synthetic peer release failure")
        self.released.append(lease)


class FakeArtifactVerifier:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.fail = False

    def verify(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("synthetic artifact verification failure")
        peer = kwargs["peer_lease"]
        profile = kwargs["peer_profile"]
        store = kwargs["staged_store"]
        return DockerOllamaStagedArtifactBinding(
            staged_store_identity_sha256=store.identity.identity_sha256,
            staged_peer_lease_proof_sha256=peer.proof_sha256,
            staging_attestation_proof_sha256=peer.staging.proof_sha256,
            peer_profile_sha256=profile.profile_sha256,
            container_id_sha256=peer.peer.container_id_sha256,
            artifact_identity_sha256="1" * 64,
            artifact_verification_proof_sha256="2" * 64,
        )


class FakeRunner:
    def run(self, argv, *, timeout_seconds):
        raise AssertionError(f"unexpected Docker command: {argv}, {timeout_seconds}")


def _supervisor():
    network = FakeNetworkSupervisor()
    peer = FakePeerSupervisor()
    artifact = FakeArtifactVerifier()
    supervisor = HalSmokeBlueInfrastructureSupervisor(
        network_supervisor=network,
        peer_supervisor=peer,
        artifact_verifier=artifact,
    )
    return supervisor, network, peer, artifact


def test_launch_closes_network_peer_and_exact_artifact_chain(tmp_path: Path) -> None:
    composition, identity = _composition()
    staged_store = _store(tmp_path, identity)
    supervisor, network, peer, artifact = _supervisor()

    lease = supervisor.launch(
        composition=composition,
        staged_store=staged_store,
        artifact_contract=_contract(),
        network_name="llmrt-hal-smoke",
    )

    assert len(network.created) == 1
    assert len(peer.launched) == 1
    assert len(artifact.calls) == 1
    assert lease.composition_sha256 == composition.composition_sha256
    assert (
        lease.target_measurement_binding_sha256
        == composition.target_measurement_binding_sha256
    )
    assert lease.peer.peer.network_id_sha256 == lease.network.network_id_sha256
    assert lease.artifact.container_id_sha256 == lease.peer.peer.container_id_sha256
    assert len(lease.proof_sha256) == 64


def test_build_trial_provider_binds_stable_identity_and_live_artifact_proof(
    tmp_path: Path,
) -> None:
    composition, identity = _composition()
    staged_store = _store(tmp_path / "store", identity)
    supervisor, _, _, _ = _supervisor()
    lease = supervisor.launch(
        composition=composition,
        staged_store=staged_store,
        artifact_contract=_contract(),
        network_name="llmrt-hal-smoke",
    )
    template = tmp_path / "template"
    template.mkdir()
    (template / "README.md").write_text("synthetic\n", encoding="utf-8")
    workspaces = DisposableWorkspaceSupervisor(
        template_root=template,
        sandbox_root=tmp_path / "sandboxes",
    )

    provider = supervisor.build_trial_provider(
        lease=lease,
        provider_id="hal-smoke-blue",
        workspace_supervisor=workspaces,
        runtime_supervisor=SimpleNamespace(),
        runner=FakeRunner(),
    )

    assert (
        provider.target_measurement_binding_sha256
        == composition.target_measurement_binding_sha256
    )
    assert provider.model_peer_runtime_proof_sha256 == lease.artifact.proof_sha256
    assert (
        provider.declared_target.identity.configuration_hash
        != composition.target_config.id
    )
    assert "measurement_identity_bound" in provider.declared_target.identity.capabilities


def test_release_preserves_network_until_peer_teardown_succeeds(tmp_path: Path) -> None:
    composition, identity = _composition()
    supervisor, network, peer, _ = _supervisor()
    lease = supervisor.launch(
        composition=composition,
        staged_store=_store(tmp_path, identity),
        artifact_contract=_contract(),
        network_name="llmrt-hal-smoke",
    )

    peer.fail_release = True
    first = supervisor.release(lease)
    assert first.cleanup_complete is False
    assert first.peer_released is False
    assert first.network_released is False
    assert network.released == []

    peer.fail_release = False
    second = supervisor.release(lease)
    assert second.cleanup_complete is True
    assert second.peer_released is True
    assert second.network_released is True
    assert len(peer.released) == 1
    assert len(network.released) == 1


def test_artifact_verification_failure_cleans_peer_then_network(tmp_path: Path) -> None:
    composition, identity = _composition()
    supervisor, network, peer, artifact = _supervisor()
    artifact.fail = True

    with pytest.raises(RuntimeError, match="synthetic artifact verification"):
        supervisor.launch(
            composition=composition,
            staged_store=_store(tmp_path, identity),
            artifact_contract=_contract(),
            network_name="llmrt-hal-smoke",
        )

    assert len(peer.released) == 1
    assert len(network.released) == 1


def test_static_artifact_drift_is_rejected_before_docker(tmp_path: Path) -> None:
    composition, identity = _composition()
    supervisor, network, peer, artifact = _supervisor()
    bad_contract = OllamaArtifactContract(
        model_id=_BLUE,
        expected_manifest_digest="sha256:" + "9" * 64,
        require_local=True,
    )

    with pytest.raises(ValueError, match="contract digest differs"):
        supervisor.launch(
            composition=composition,
            staged_store=_store(tmp_path, identity),
            artifact_contract=bad_contract,
            network_name="llmrt-hal-smoke",
        )

    assert network.created == []
    assert peer.launched == []
    assert artifact.calls == []
