import json
from collections import deque
from hashlib import sha256

import pytest

from llm_redteam.docker_model_peer import (
    DockerModelPeerLease,
    DockerModelPeerProfile,
    DockerModelPeerReadinessObservation,
)
from llm_redteam.docker_ollama_artifact import (
    DockerOllamaArtifactVerifier,
    OllamaDockerArtifactProbeProfile,
)
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.ollama_artifact import OllamaArtifactContract

_CONTAINER_ID = "c" * 64
_OTHER_ID = "d" * 64
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


def _peer_profile(
    *,
    provider_id: str = "ollama",
    model_id: str = "qwen-local",
) -> DockerModelPeerProfile:
    return DockerModelPeerProfile(
        provider_id=provider_id,
        model_id=model_id,
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        command=("ollama", "serve"),
        readiness_command=("synthetic-readiness",),
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
    )


def _peer_lease(profile: DockerModelPeerProfile | None = None) -> DockerModelPeerLease:
    peer = profile or _peer_profile()
    readiness = DockerModelPeerReadinessObservation(
        provider_id=peer.provider_id,
        model_id=peer.model_id,
        profile_sha256=peer.profile_sha256,
        container_id_sha256=_digest(_CONTAINER_ID),
        response_sha256="1" * 64,
        ready=True,
    )
    return DockerModelPeerLease(
        container_name="model-peer",
        container_id_sha256=_digest(_CONTAINER_ID),
        profile_sha256=peer.profile_sha256,
        network_id_sha256="2" * 64,
        launch_command_sha256="3" * 64,
        readiness=readiness,
    )


def _contract(*, digest: str = _MANIFEST_DIGEST) -> OllamaArtifactContract:
    return OllamaArtifactContract(
        model_id="qwen-local",
        expected_manifest_digest=digest,
        require_local=True,
    )


def _probe(profile: DockerModelPeerProfile | None = None) -> OllamaDockerArtifactProbeProfile:
    peer = profile or _peer_profile()
    return OllamaDockerArtifactProbeProfile(
        peer_profile_sha256=peer.profile_sha256,
        inventory_command=("synthetic-ollama-tags-json",),
    )


def _inspect(container_id: str = _CONTAINER_ID) -> CommandResult:
    return CommandResult(returncode=0, stdout=json.dumps([{"Id": container_id}]))


def _inventory(*, digest: str = _MANIFEST_DIGEST) -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps(
            {
                "models": [
                    {
                        "name": "qwen-local",
                        "size": 7_000_000_000,
                        "digest": digest,
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


def test_verifier_binds_owned_peer_to_exact_manifest_without_inference() -> None:
    profile = _peer_profile()
    runner = FakeRunner([_inspect(), _inventory(), _inspect()])

    verification = DockerOllamaArtifactVerifier(runner).verify(
        peer_profile=profile,
        peer_lease=_peer_lease(profile),
        contract=_contract(),
        probe_profile=_probe(profile),
    )

    assert runner.calls[1] == (
        "docker",
        "exec",
        "model-peer",
        "synthetic-ollama-tags-json",
    )
    assert verification.artifact.identity.artifact_digest == "sha256:" + _MANIFEST_DIGEST
    assert verification.artifact.identity.local_artifact is True
    assert verification.binding.peer_profile_sha256 == profile.profile_sha256
    assert verification.binding.artifact_identity_sha256 == (
        verification.artifact.identity.identity_sha256
    )
    assert len(verification.proof_sha256) == 64


def test_verifier_rejects_manifest_drift() -> None:
    profile = _peer_profile()
    runner = FakeRunner([_inspect(), _inventory(digest="f" * 64), _inspect()])

    with pytest.raises(ValueError, match="manifest digest"):
        DockerOllamaArtifactVerifier(runner).verify(
            peer_profile=profile,
            peer_lease=_peer_lease(profile),
            contract=_contract(),
            probe_profile=_probe(profile),
        )


def test_verifier_rejects_container_name_reuse_after_inventory_probe() -> None:
    profile = _peer_profile()
    runner = FakeRunner([_inspect(), _inventory(), _inspect(_OTHER_ID)])

    with pytest.raises(RuntimeError, match="no longer owns"):
        DockerOllamaArtifactVerifier(runner).verify(
            peer_profile=profile,
            peer_lease=_peer_lease(profile),
            contract=_contract(),
            probe_profile=_probe(profile),
        )


def test_verifier_rejects_provider_or_model_drift_before_docker_calls() -> None:
    wrong_provider = _peer_profile(provider_id="other")
    provider_runner = FakeRunner([])
    with pytest.raises(ValueError, match="provider_id=ollama"):
        DockerOllamaArtifactVerifier(provider_runner).verify(
            peer_profile=wrong_provider,
            peer_lease=_peer_lease(wrong_provider),
            contract=_contract(),
            probe_profile=_probe(wrong_provider),
        )
    assert provider_runner.calls == []

    wrong_model = _peer_profile(model_id="other-model")
    model_runner = FakeRunner([])
    with pytest.raises(ValueError, match="contract model"):
        DockerOllamaArtifactVerifier(model_runner).verify(
            peer_profile=wrong_model,
            peer_lease=_peer_lease(wrong_model),
            contract=_contract(),
            probe_profile=_probe(wrong_model),
        )
    assert model_runner.calls == []


def test_probe_profile_must_bind_exact_peer_profile() -> None:
    profile = _peer_profile()
    other = _peer_profile(model_id="another-model")
    runner = FakeRunner([])

    with pytest.raises(ValueError, match="probe profile"):
        DockerOllamaArtifactVerifier(runner).verify(
            peer_profile=profile,
            peer_lease=_peer_lease(profile),
            contract=_contract(),
            probe_profile=_probe(other),
        )

    assert runner.calls == []
