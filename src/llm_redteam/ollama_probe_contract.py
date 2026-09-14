"""Stable runtime contract for the laboratory-owned Ollama peer probe image."""

from __future__ import annotations

from .docker_ollama_artifact import OllamaDockerArtifactProbeProfile
from .docker_ollama_staged_peer import DockerOllamaStagedPeerProfile
from .ollama_model_staging import PreparedOllamaModelStore

_PROBE_PATH = "/usr/local/bin/rt-ollama-probe"


def build_probed_staged_ollama_peer(
    *,
    model_id: str,
    image_ref: str,
    image_id: str,
    staged_store: PreparedOllamaModelStore,
    memory_limit_bytes: int,
    pids_limit: int,
    cpus: float,
    gpu_access: bool,
) -> tuple[DockerOllamaStagedPeerProfile, OllamaDockerArtifactProbeProfile]:
    """Create matching peer/readiness/artifact-probe profiles from one staged artifact."""

    if staged_store.identity.model_id != model_id:
        raise ValueError("staged store model does not match requested Ollama model")
    peer = DockerOllamaStagedPeerProfile(
        provider_id="ollama",
        model_id=model_id,
        image_ref=image_ref,
        image_id=image_id,
        command=("serve",),
        readiness_command=(_PROBE_PATH, "version"),
        readiness_required_json={"provider": "ollama", "ready": True},
        memory_limit_bytes=memory_limit_bytes,
        pids_limit=pids_limit,
        cpus=cpus,
        gpu_access=gpu_access,
        staged_store_identity_sha256=staged_store.identity.identity_sha256,
    )
    artifact_probe = OllamaDockerArtifactProbeProfile(
        peer_profile_sha256=peer.profile_sha256,
        inventory_command=(_PROBE_PATH, "tags"),
    )
    return peer, artifact_probe
