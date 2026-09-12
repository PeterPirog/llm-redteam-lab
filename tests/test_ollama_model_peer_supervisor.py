import json
from collections import deque
from hashlib import sha256
from pathlib import Path

import pytest

import llm_redteam.ollama_model_peer_supervisor as supervisor_module
from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_model_peer import DockerModelPeerProfile
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.model_artifact import ModelPeerArtifactBinding
from llm_redteam.ollama_artifact_bundle import (
    OllamaArtifactBundleContract,
    OllamaArtifactBundleVerification,
    OllamaBundleBlob,
)
from llm_redteam.ollama_model_peer import compose_ollama_model_peer_profile
from llm_redteam.ollama_model_peer_supervisor import OllamaModelPeerSupervisor

_CONTAINER_ID = "a" * 64
_OTHER_ID = "b" * 64
_NETWORK_ID = "c" * 64
_NETWORK_NAME = "rt-model-net"
_IMAGE_REF = "ollama/ollama@sha256:" + "d" * 64
_IMAGE_ID = "sha256:" + "e" * 64
_ARTIFACT_IDENTITY = "1" * 64
_MANIFEST_HEX = "2" * 64
_BUNDLE_PATH = Path("C:/synthetic/qualified-model")


class FakeRunner:
    def __init__(self, results: list[CommandResult]) -> None:
        self.results = deque(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds > 0
        self.calls.append(argv)
        if not self.results:
            raise AssertionError(f"unexpected Docker command: {argv}")
        return self.results.popleft()


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _network_lease() -> DockerModelNetworkLease:
    network = _network()
    return DockerModelNetworkLease(
        network_name=_NETWORK_NAME,
        network_id_sha256=_digest(_NETWORK_ID),
        network_profile_sha256=network.profile_sha256,
        create_command_sha256="3" * 64,
        engine=DockerEngineVersionObservation(
            server_version="28.0.0",
            major=28,
            minor=0,
            patch=0,
            command_sha256="4" * 64,
        ),
    )


def _peer() -> DockerModelPeerProfile:
    return DockerModelPeerProfile(
        provider_id="ollama",
        model_id="qwen-test:latest",
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        command=("ollama", "serve"),
        readiness_command=("python", "-c", "print_ready_json"),
        readiness_required_json={"healthy": True},
        memory_limit_bytes=8 * 1024 * 1024 * 1024,
        pids_limit=256,
        cpus=4.0,
        gpu_access=True,
    )


def _bundle(peer: DockerModelPeerProfile) -> OllamaArtifactBundleContract:
    return OllamaArtifactBundleContract(
        model_id=peer.model_id,
        artifact_identity_sha256=_ARTIFACT_IDENTITY,
        artifact_size_bytes=42,
        manifest_digest="sha256:" + _MANIFEST_HEX,
        manifest_relative_path="registry.ollama.ai/library/qwen-test/latest",
        blobs=(
            OllamaBundleBlob(
                digest="sha256:" + "5" * 64,
                size_bytes=42,
                media_types=("application/vnd.ollama.image.model",),
            ),
        ),
    )


def _verification(bundle: OllamaArtifactBundleContract, *, marker: str = "6") -> OllamaArtifactBundleVerification:
    return OllamaArtifactBundleVerification(
        contract_sha256=bundle.bundle_sha256,
        manifest_sha256=_MANIFEST_HEX,
        blob_inventory_sha256=marker * 64,
        blob_count=1,
        total_blob_bytes=42,
    )


def _profile():
    peer = _peer()
    bundle = _bundle(peer)
    verification = _verification(bundle)
    binding = ModelPeerArtifactBinding(
        peer_profile_sha256=peer.profile_sha256,
        provider_id=peer.provider_id,
        model_id=peer.model_id,
        artifact_identity_sha256=_ARTIFACT_IDENTITY,
    )
    profile = compose_ollama_model_peer_profile(
        peer=peer,
        artifact_binding=binding,
        bundle_contract=bundle,
        bundle_verification=verification,
    )
    return peer, bundle, verification, profile


def _network_inspect(network_id: str = _NETWORK_ID) -> CommandResult:
    return CommandResult(returncode=0, stdout=json.dumps([{"Id": network_id}]))


def _container_inspect(
    peer: DockerModelPeerProfile,
    container_id: str = _CONTAINER_ID,
) -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps(
            [
                {
                    "Id": container_id,
                    "Image": _IMAGE_ID,
                    "State": {"Running": True},
                    "HostConfig": {
                        "AutoRemove": True,
                        "Privileged": False,
                        "ReadonlyRootfs": True,
                        "NetworkMode": _NETWORK_NAME,
                        "CapAdd": None,
                        "CapDrop": ["ALL"],
                        "SecurityOpt": ["no-new-privileges:true"],
                        "PidsLimit": peer.pids_limit,
                        "Memory": peer.memory_limit_bytes,
                        "NanoCpus": int(peer.cpus * 1_000_000_000),
                        "PortBindings": {},
                        "DeviceRequests": [{"Capabilities": [["gpu"]]}],
                    },
                    "NetworkSettings": {"Networks": {_NETWORK_NAME: {}}},
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": "/run/desktop/mnt/host/c/synthetic/qualified-model",
                            "Destination": "/models",
                            "RW": False,
                        }
                    ],
                    "Config": {"Env": ["OLLAMA_MODELS=/models"]},
                }
            ]
        ),
    )


def _launch_results(peer: DockerModelPeerProfile) -> list[CommandResult]:
    return [
        _network_inspect(),
        CommandResult(returncode=0, stdout=_CONTAINER_ID + "\n"),
        _container_inspect(peer),
        _network_inspect(),
        _container_inspect(peer),
        CommandResult(returncode=0, stdout='{"healthy":true}'),
        _container_inspect(peer),
    ]


def test_launch_reverifies_bundle_and_returns_exact_owned_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, bundle, verification, profile = _profile()
    verification_calls: list[Path] = []

    def verify(*, models_root: Path, contract: OllamaArtifactBundleContract):
        assert contract == bundle
        verification_calls.append(models_root)
        return verification

    monkeypatch.setattr(supervisor_module, "verify_ollama_artifact_bundle", verify)
    runner = FakeRunner(_launch_results(peer))
    supervisor = OllamaModelPeerSupervisor(runner=runner)

    lease = supervisor.launch(
        profile=profile,
        peer=peer,
        bundle_contract=bundle,
        bundle_host_path=_BUNDLE_PATH,
        network_profile=_network(),
        network_lease=_network_lease(),
    )

    assert verification_calls == [_BUNDLE_PATH, _BUNDLE_PATH]
    assert lease.container_id_sha256 == _digest(_CONTAINER_ID)
    assert lease.bundle_contract_sha256 == bundle.bundle_sha256
    assert lease.prelaunch_bundle_proof_sha256 == verification.proof_sha256
    assert lease.readiness.ready is True
    assert runner.calls[0] == ("docker", "network", "inspect", _NETWORK_NAME)
    assert runner.calls[1][0:2] == ("docker", "run")
    assert runner.calls[5][0:3] == ("docker", "exec", "model-peer")


def test_prelaunch_artifact_drift_fails_before_any_docker_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, bundle, _, profile = _profile()
    drifted = _verification(bundle, marker="7")
    monkeypatch.setattr(
        supervisor_module,
        "verify_ollama_artifact_bundle",
        lambda **_: drifted,
    )
    runner = FakeRunner([])

    with pytest.raises(ValueError, match="no longer matches qualified proof"):
        OllamaModelPeerSupervisor(runner=runner).launch(
            profile=profile,
            peer=peer,
            bundle_contract=bundle,
            bundle_host_path=_BUNDLE_PATH,
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert runner.calls == []


def test_postlaunch_bundle_drift_removes_only_owned_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, bundle, verification, profile = _profile()
    drifted = _verification(bundle, marker="8")
    verifications = iter((verification, drifted))
    monkeypatch.setattr(
        supervisor_module,
        "verify_ollama_artifact_bundle",
        lambda **_: next(verifications),
    )
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(returncode=0, stdout=_CONTAINER_ID),
            _container_inspect(peer),
            _network_inspect(),
            _container_inspect(peer),
            CommandResult(returncode=0),
        ]
    )

    with pytest.raises(RuntimeError, match="changed during model-peer launch"):
        OllamaModelPeerSupervisor(runner=runner).launch(
            profile=profile,
            peer=peer,
            bundle_contract=bundle,
            bundle_host_path=_BUNDLE_PATH,
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert runner.calls[-1] == ("docker", "rm", "--force", "model-peer")


def test_name_reuse_after_rejection_is_never_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, bundle, verification, profile = _profile()
    drifted = _verification(bundle, marker="8")
    verifications = iter((verification, drifted))
    monkeypatch.setattr(
        supervisor_module,
        "verify_ollama_artifact_bundle",
        lambda **_: next(verifications),
    )
    runner = FakeRunner(
        [
            _network_inspect(),
            CommandResult(returncode=0, stdout=_CONTAINER_ID),
            _container_inspect(peer),
            _network_inspect(),
            _container_inspect(peer, container_id=_OTHER_ID),
        ]
    )

    with pytest.raises(RuntimeError, match="changed during model-peer launch"):
        OllamaModelPeerSupervisor(runner=runner).launch(
            profile=profile,
            peer=peer,
            bundle_contract=bundle,
            bundle_host_path=_BUNDLE_PATH,
            network_profile=_network(),
            network_lease=_network_lease(),
        )

    assert not any(call[:3] == ("docker", "rm", "--force") for call in runner.calls)


def test_release_reports_integrity_and_cleans_owned_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, bundle, verification, profile = _profile()
    monkeypatch.setattr(
        supervisor_module,
        "verify_ollama_artifact_bundle",
        lambda **_: verification,
    )
    launch_runner = FakeRunner(_launch_results(peer))
    lease = OllamaModelPeerSupervisor(runner=launch_runner).launch(
        profile=profile,
        peer=peer,
        bundle_contract=bundle,
        bundle_host_path=_BUNDLE_PATH,
        network_profile=_network(),
        network_lease=_network_lease(),
    )

    release_runner = FakeRunner(
        [
            _container_inspect(peer),
            CommandResult(returncode=0),
            CommandResult(returncode=1),
        ]
    )
    release = OllamaModelPeerSupervisor(runner=release_runner).release(
        lease=lease,
        bundle_contract=bundle,
        bundle_host_path=_BUNDLE_PATH,
    )

    assert release.cleanup_complete is True
    assert release.artifact_contract_matched is True
    assert release.artifact_stable is True
    assert release.post_bundle_proof_sha256 == verification.proof_sha256
    assert release_runner.calls[1][0:2] == ("docker", "stop")


def test_wrong_release_contract_does_not_block_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer, bundle, verification, profile = _profile()
    monkeypatch.setattr(
        supervisor_module,
        "verify_ollama_artifact_bundle",
        lambda **_: verification,
    )
    lease = OllamaModelPeerSupervisor(runner=FakeRunner(_launch_results(peer))).launch(
        profile=profile,
        peer=peer,
        bundle_contract=bundle,
        bundle_host_path=_BUNDLE_PATH,
        network_profile=_network(),
        network_lease=_network_lease(),
    )
    wrong_bundle = bundle.model_copy(update={"manifest_relative_path": "x/y/z/other"})
    called = False

    def must_not_verify(**_: object):
        nonlocal called
        called = True
        raise AssertionError("wrong release contract must not be verified")

    monkeypatch.setattr(supervisor_module, "verify_ollama_artifact_bundle", must_not_verify)
    release_runner = FakeRunner(
        [_container_inspect(peer), CommandResult(returncode=0), CommandResult(returncode=1)]
    )
    release = OllamaModelPeerSupervisor(runner=release_runner).release(
        lease=lease,
        bundle_contract=wrong_bundle,
        bundle_host_path=_BUNDLE_PATH,
    )

    assert called is False
    assert release.cleanup_complete is True
    assert release.artifact_contract_matched is False
    assert release.artifact_stable is False
    assert release.post_bundle_proof_sha256 is None
