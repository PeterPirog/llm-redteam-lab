"""Trusted lifecycle for one verified Ollama model peer in an isolated AGENT trial.

The supervisor composes ADR-060 model-peer confinement with ADR-063/064 artifact
qualification. It verifies the exact staged bundle before launch and again after launch,
proves network/container ownership independently from the model process, performs only a
non-inference readiness check, and tears down only the exact owned container.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_network_supervisor import DockerModelNetworkLease
from .docker_model_peer import (
    DockerModelPeerProfile,
    DockerModelPeerReadinessObservation,
)
from .docker_supervisor import DockerCommandRunner, SubprocessDockerCommandRunner
from .domain import StrictModel
from .ollama_artifact_bundle import (
    OllamaArtifactBundleContract,
    OllamaArtifactBundleVerification,
    verify_ollama_artifact_bundle,
)
from .ollama_model_peer import (
    OllamaModelPeerAttestation,
    OllamaModelPeerProfile,
    attest_ollama_model_peer_inspection,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class OllamaModelPeerLease(StrictModel):
    """Per-run ownership and artifact-integrity token for one Ollama peer."""

    container_name: str = Field(min_length=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    network_id_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_command_sha256: str = Field(pattern=_HASH_PATTERN)
    prelaunch_bundle_proof_sha256: str = Field(pattern=_HASH_PATTERN)
    inspection: OllamaModelPeerAttestation
    readiness: DockerModelPeerReadinessObservation


class OllamaModelPeerRelease(StrictModel):
    """Teardown evidence; artifact drift is reported without blocking cleanup."""

    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    cleanup_complete: bool
    artifact_stable: bool
    post_bundle_proof_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class OllamaModelPeerSupervisor:
    """Launch, verify readiness and release one exact verified Ollama peer."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 30.0,
        readiness_timeout_seconds: float = 120.0,
        stop_timeout_seconds: int = 5,
    ) -> None:
        if command_timeout_seconds <= 0 or readiness_timeout_seconds <= 0:
            raise ValueError("Ollama model-peer timeouts must be positive")
        if stop_timeout_seconds < 0:
            raise ValueError("stop_timeout_seconds cannot be negative")
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds
        self._readiness_timeout_seconds = readiness_timeout_seconds
        self._stop_timeout_seconds = stop_timeout_seconds

    def launch(
        self,
        *,
        profile: OllamaModelPeerProfile,
        peer: DockerModelPeerProfile,
        bundle_contract: OllamaArtifactBundleContract,
        bundle_host_path: Path,
        network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
    ) -> OllamaModelPeerLease:
        """Admit only an exact verified bundle on the still-owned isolated network."""

        if network_lease.network_profile_sha256 != network_profile.profile_sha256:
            raise ValueError("model-network lease does not bind the requested profile")
        if bundle_contract.bundle_sha256 != profile.bundle_contract_sha256:
            raise ValueError("Ollama bundle contract does not bind the runtime profile")

        prelaunch = verify_ollama_artifact_bundle(
            models_root=bundle_host_path,
            contract=bundle_contract,
        )
        if prelaunch.proof_sha256 != profile.bundle_verification_proof_sha256:
            raise ValueError("staged Ollama bundle no longer matches qualified proof")

        self._require_owned_network(network_lease)
        launch_command = profile.docker_run_command(
            peer=peer,
            network_profile=network_profile,
            network_name=network_lease.network_name,
            bundle_host_path=bundle_host_path,
        )
        result = self._runner.run(
            launch_command,
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker Ollama model-peer launch failed")
        container_id = _parse_full_id(result.stdout)
        container_name = network_profile.model_endpoint_host

        try:
            raw = self._inspect_container(container_name)
            if _required_id(raw) != container_id:
                raise RuntimeError("Docker Ollama peer ownership changed before attestation")
            inspection = attest_ollama_model_peer_inspection(
                profile=profile,
                peer=peer,
                payload=raw,
                bundle_host_path=bundle_host_path,
                expected_network_name=network_lease.network_name,
            )
            self._require_owned_network(network_lease)

            postlaunch = verify_ollama_artifact_bundle(
                models_root=bundle_host_path,
                contract=bundle_contract,
            )
            if postlaunch != prelaunch:
                raise RuntimeError("Ollama bundle changed during model-peer launch")

            readiness = self._probe_readiness(
                peer=peer,
                container_name=container_name,
                container_id=container_id,
            )
        except Exception:
            self._remove_if_owned(container_name, container_id)
            raise

        return OllamaModelPeerLease(
            container_name=container_name,
            container_id_sha256=sha256(container_id.encode()).hexdigest(),
            profile_sha256=profile.profile_sha256,
            network_id_sha256=network_lease.network_id_sha256,
            launch_command_sha256=canonical_json_hash(list(launch_command)),
            prelaunch_bundle_proof_sha256=prelaunch.proof_sha256,
            inspection=inspection,
            readiness=readiness,
        )

    def release(
        self,
        *,
        lease: OllamaModelPeerLease,
        bundle_contract: OllamaArtifactBundleContract,
        bundle_host_path: Path,
    ) -> OllamaModelPeerRelease:
        """Always prioritize exact-container cleanup, while reporting artifact drift."""

        artifact_stable = False
        post_bundle_proof: str | None = None
        try:
            verification = verify_ollama_artifact_bundle(
                models_root=bundle_host_path,
                contract=bundle_contract,
            )
            post_bundle_proof = verification.proof_sha256
            artifact_stable = post_bundle_proof == lease.prelaunch_bundle_proof_sha256
        except (OSError, ValueError, RuntimeError):
            artifact_stable = False

        self._require_owned_container(lease)
        stopped = self._runner.run(
            (
                "docker",
                "stop",
                "--time",
                str(self._stop_timeout_seconds),
                lease.container_name,
            ),
            timeout_seconds=self._command_timeout_seconds,
        )
        if stopped.returncode != 0:
            removed = self._runner.run(
                ("docker", "rm", "--force", lease.container_name),
                timeout_seconds=self._command_timeout_seconds,
            )
            if removed.returncode != 0:
                raise RuntimeError("Docker Ollama model-peer teardown failed")

        post = self._runner.run(
            ("docker", "inspect", "--type", "container", lease.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if post.returncode == 0:
            try:
                remaining_id = _required_id(_parse_single_record(post.stdout))
            except (ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("Docker Ollama peer removal could not be verified") from exc
            if sha256(remaining_id.encode()).hexdigest() == lease.container_id_sha256:
                raise RuntimeError("Docker Ollama model peer still exists after teardown")
            raise RuntimeError("Docker Ollama model-peer name was reused during teardown")

        return OllamaModelPeerRelease(
            container_id_sha256=lease.container_id_sha256,
            cleanup_complete=True,
            artifact_stable=artifact_stable,
            post_bundle_proof_sha256=post_bundle_proof,
        )

    def _probe_readiness(
        self,
        *,
        peer: DockerModelPeerProfile,
        container_name: str,
        container_id: str,
    ) -> DockerModelPeerReadinessObservation:
        self._require_raw_container_id(container_name, container_id)
        result = self._runner.run(
            ("docker", "exec", container_name, *peer.readiness_command),
            timeout_seconds=self._readiness_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker Ollama model-peer readiness command failed")
        self._require_raw_container_id(container_name, container_id)
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Docker Ollama readiness output is not JSON") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Docker Ollama readiness output must be a JSON object")
        for key, expected in peer.readiness_required_json.items():
            if payload.get(key) != expected:
                raise RuntimeError(
                    f"Docker Ollama readiness requirement failed for key {key!r}"
                )
        return DockerModelPeerReadinessObservation(
            provider_id=peer.provider_id,
            model_id=peer.model_id,
            profile_sha256=peer.profile_sha256,
            container_id_sha256=sha256(container_id.encode()).hexdigest(),
            response_sha256=canonical_json_hash(payload),
            ready=True,
        )

    def _require_owned_network(self, lease: DockerModelNetworkLease) -> None:
        result = self._runner.run(
            ("docker", "network", "inspect", lease.network_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker model-network lease is no longer inspectable")
        try:
            network_id = _required_id(_parse_single_record(result.stdout))
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker model-network ownership proof is invalid") from exc
        if sha256(network_id.encode()).hexdigest() != lease.network_id_sha256:
            raise RuntimeError("Docker model-network lease no longer owns the network")

    def _inspect_container(self, container_name: str) -> dict[str, object]:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("Docker Ollama model-peer inspection failed")
        try:
            return _parse_single_record(result.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Docker Ollama inspection payload is invalid") from exc

    def _require_raw_container_id(self, container_name: str, expected_id: str) -> None:
        if _required_id(self._inspect_container(container_name)) != expected_id:
            raise RuntimeError("Docker Ollama peer ownership changed during readiness probe")

    def _require_owned_container(self, lease: OllamaModelPeerLease) -> None:
        current_id = _required_id(self._inspect_container(lease.container_name))
        if sha256(current_id.encode()).hexdigest() != lease.container_id_sha256:
            raise RuntimeError("Docker Ollama model-peer lease no longer owns the container")

    def _remove_if_owned(self, container_name: str, expected_id: str) -> None:
        result = self._runner.run(
            ("docker", "inspect", "--type", "container", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            return
        try:
            current_id = _required_id(_parse_single_record(result.stdout))
        except (ValueError, json.JSONDecodeError):
            return
        if current_id != expected_id:
            return
        removed = self._runner.run(
            ("docker", "rm", "--force", container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if removed.returncode != 0:
            raise RuntimeError("Docker Ollama cleanup failed after rejected attestation")


def _parse_full_id(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("Docker Ollama launch did not return exactly one container ID")
    value = lines[0].casefold()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("Docker Ollama launch returned an invalid full container ID")
    return value


def _parse_single_record(stdout: str) -> dict[str, object]:
    payload = json.loads(stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise ValueError("Docker inspect must return exactly one record")
    record = payload[0]
    if not isinstance(record, dict):
        raise ValueError("Docker inspect record must be an object")
    return record


def _required_id(payload: dict[str, object]) -> str:
    value = payload.get("Id")
    if not isinstance(value, str) or not value:
        raise ValueError("Docker inspect Id must be a non-empty string")
    return value
