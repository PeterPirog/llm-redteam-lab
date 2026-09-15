import json
from collections import deque
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.docker_model_peer import (
    DockerModelPeerLease,
    DockerModelPeerReadinessObservation,
)
from llm_redteam.docker_ollama_artifact import OllamaDockerArtifactProbeProfile
from llm_redteam.docker_ollama_staged_artifact import (
    DockerOllamaStagedArtifactVerifier,
)
from llm_redteam.docker_ollama_staged_peer import (
    DockerOllamaStagedPeerAttestation,
    DockerOllamaStagedPeerProfile,
)
from llm_redteam.docker_ollama_staged_peer_supervisor import (
    DockerOllamaStagedPeerLease,
)
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.ollama_model_staging import (
    OllamaStagedModelStoreIdentity,
    PreparedOllamaModelStore,
)

_CONTAINER_ID = "c" * 64
_MANIFEST_DIGEST = "e" * 64
_IMAGE_ID = "sha256:" + "a" * 64
_IMAGE_REF = "synthetic/ollama@sha256:" + "b" * 64


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = deque(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.calls.append(argv)
        if not self.results:
            raise AssertionError(f"unexpected command: {argv}")
        return self.results.popleft()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _store(tmp_path: Path) -> PreparedOllamaModelStore:
    models = tmp_path / "models"
    models.mkdir(parents=True)
    identity = OllamaStagedModelStoreIdentity(
        model_id="qwen-local",
        manifest_digest="sha256:" + _MANIFEST_DIGEST,
        manifest_relative_path_sha256="1" * 64,
        staged_tree_sha256="2" * 64,
        referenced_blob_count=2,
        referenced_blob_bytes=1024,
    )
    return PreparedOllamaModelStore(models_path=models, identity=identity)


def _profile(store: PreparedOllamaModelStore) -> DockerOllamaStagedPeerProfile:
    return DockerOllamaStagedPeerProfile(
        provider_id="ollama",
        model_id="qwen-local",
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        command=("ollama", "serve"),
        readiness_command=("/usr/local/bin/rt-ollama-probe", "version"),
        readiness_required_json={"provider": "ollama", "ready": True},
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
        staged_store_identity_sha256=store.identity.identity_sha256,
    )


def _lease(
    store: PreparedOllamaModelStore,
    profile: DockerOllamaStagedPeerProfile,
) -> DockerOllamaStagedPeerLease:
    container_hash = _digest(_CONTAINER_ID)
    readiness = DockerModelPeerReadinessObservation(
        provider_id="ollama",
        model_id="qwen-local",
        profile_sha256=profile.profile_sha256,
        container_id_sha256=container_hash,
        response_sha256="3" * 64,
        ready=True,
    )
    peer = DockerModelPeerLease(
        container_name="model-peer",
        container_id_sha256=container_hash,
        profile_sha256=profile.profile_sha256,
        network_id_sha256="4" * 64,
        launch_command_sha256="5" * 64,
        readiness=readiness,
    )
    staging = DockerOllamaStagedPeerAttestation(
        peer_profile_sha256=profile.profile_sha256,
        staged_store_identity_sha256=store.identity.identity_sha256,
        container_id_sha256=container_hash,
        mount_source_sha256="6" * 64,
        inspection_sha256="7" * 64,
    )
    return DockerOllamaStagedPeerLease(
        peer=peer,
        staging=staging,
        staged_store_identity_sha256=store.identity.identity_sha256,
    )


def _inspect() -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps([{"Id": _CONTAINER_ID}]),
    )


def _tags(*, digest: str = _MANIFEST_DIGEST) -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps(
            {
                "models": [
                    {
                        "name": "qwen-local",
                        "digest": digest,
                        "size": 7_000_000_000,
                        "details": {
                            "format": "gguf",
                            "family": "qwen",
                            "parameter_size": "9B",
                            "quantization_level": "Q4_K_M",
                        },
                    }
                ]
            }
        ),
    )


def test_binding_closes_store_peer_artifact_chain_and_canonicalizes_digest(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    lease = _lease(store, profile)
    runner = FakeRunner([_inspect(), _tags(), _inspect()])

    binding = DockerOllamaStagedArtifactVerifier(runner).verify(
        peer_profile=profile,
        peer_lease=lease,
        staged_store=store,
        contract=OllamaArtifactContract(
            model_id="qwen-local",
            expected_manifest_digest=_MANIFEST_DIGEST,
            require_local=True,
        ),
        probe_profile=OllamaDockerArtifactProbeProfile(
            peer_profile_sha256=profile.profile_sha256
        ),
    )

    assert runner.calls[1] == (
        "docker",
        "exec",
        "model-peer",
        "/usr/local/bin/rt-ollama-probe",
        "tags",
    )
    assert binding.staged_store_identity_sha256 == store.identity.identity_sha256
    assert binding.peer_profile_sha256 == profile.profile_sha256
    assert binding.container_id_sha256 == lease.peer.container_id_sha256
    assert len(binding.artifact_identity_sha256) == 64
    assert len(binding.proof_sha256) == 64


def test_contract_stage_digest_drift_fails_before_probe(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    runner = FakeRunner([])

    with pytest.raises(ValueError, match="digest does not match staged store"):
        DockerOllamaStagedArtifactVerifier(runner).verify(
            peer_profile=profile,
            peer_lease=_lease(store, profile),
            staged_store=store,
            contract=OllamaArtifactContract(
                model_id="qwen-local",
                expected_manifest_digest="f" * 64,
                require_local=True,
            ),
            probe_profile=OllamaDockerArtifactProbeProfile(
                peer_profile_sha256=profile.profile_sha256
            ),
        )

    assert runner.calls == []


def test_staging_container_drift_fails_before_probe(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    lease = _lease(store, profile)
    bad_staging = lease.staging.model_copy(update={"container_id_sha256": "8" * 64})
    drifted = lease.model_copy(update={"staging": bad_staging})
    runner = FakeRunner([])

    with pytest.raises(ValueError, match="leased container"):
        DockerOllamaStagedArtifactVerifier(runner).verify(
            peer_profile=profile,
            peer_lease=drifted,
            staged_store=store,
            contract=OllamaArtifactContract(
                model_id="qwen-local",
                expected_manifest_digest="sha256:" + _MANIFEST_DIGEST,
                require_local=True,
            ),
            probe_profile=OllamaDockerArtifactProbeProfile(
                peer_profile_sha256=profile.profile_sha256
            ),
        )

    assert runner.calls == []


def test_runtime_manifest_drift_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    profile = _profile(store)
    runner = FakeRunner([_inspect(), _tags(digest="f" * 64), _inspect()])

    with pytest.raises(ValueError, match="manifest digest"):
        DockerOllamaStagedArtifactVerifier(runner).verify(
            peer_profile=profile,
            peer_lease=_lease(store, profile),
            staged_store=store,
            contract=OllamaArtifactContract(
                model_id="qwen-local",
                expected_manifest_digest=_MANIFEST_DIGEST,
                require_local=True,
            ),
            probe_profile=OllamaDockerArtifactProbeProfile(
                peer_profile_sha256=profile.profile_sha256
            ),
        )
