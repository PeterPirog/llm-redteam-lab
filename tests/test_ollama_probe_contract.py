from pathlib import Path

import pytest

from llm_redteam.ollama_model_staging import (
    OllamaStagedModelStoreIdentity,
    PreparedOllamaModelStore,
)
from llm_redteam.ollama_probe_contract import build_probed_staged_ollama_peer

_IMAGE_REF = "synthetic/ollama-probe@sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64


def _store(tmp_path: Path, *, model_id: str = "qwen-local") -> PreparedOllamaModelStore:
    models = tmp_path / "models"
    models.mkdir()
    identity = OllamaStagedModelStoreIdentity(
        model_id=model_id,
        manifest_digest="sha256:" + "c" * 64,
        manifest_relative_path_sha256="d" * 64,
        staged_tree_sha256="e" * 64,
        referenced_blob_count=2,
        referenced_blob_bytes=1024,
    )
    return PreparedOllamaModelStore(models_path=models, identity=identity)


def test_factory_binds_readiness_and_inventory_to_same_probe_binary(tmp_path: Path) -> None:
    store = _store(tmp_path)

    peer, artifact_probe = build_probed_staged_ollama_peer(
        model_id="qwen-local",
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        staged_store=store,
        memory_limit_bytes=8 * 1024 * 1024 * 1024,
        pids_limit=256,
        cpus=6.0,
        gpu_access=True,
    )

    assert peer.command == ("serve",)
    assert peer.readiness_command == ("/usr/local/bin/rt-ollama-probe", "version")
    assert peer.readiness_required_json == {"provider": "ollama", "ready": True}
    assert artifact_probe.inventory_command == (
        "/usr/local/bin/rt-ollama-probe",
        "tags",
    )
    assert artifact_probe.peer_profile_sha256 == peer.profile_sha256
    assert peer.staged_store_identity_sha256 == store.identity.identity_sha256
    assert peer.gpu_access is True


def test_factory_rejects_staged_model_drift(tmp_path: Path) -> None:
    store = _store(tmp_path, model_id="other-model")

    with pytest.raises(ValueError, match="staged store model"):
        build_probed_staged_ollama_peer(
            model_id="qwen-local",
            image_ref=_IMAGE_REF,
            image_id=_IMAGE_ID,
            staged_store=store,
            memory_limit_bytes=1024 * 1024 * 1024,
            pids_limit=128,
            cpus=2.0,
            gpu_access=False,
        )
