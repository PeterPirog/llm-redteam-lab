import json
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.ollama_model_staging import OllamaModelStagingSupervisor

_MODEL_ID = "qwen-local"
_MANIFEST_RELATIVE = "registry.ollama.ai/library/qwen-local/latest"


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _source_store(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    models = tmp_path / "source-models"
    manifests = models / "manifests" / "registry.ollama.ai" / "library" / "qwen-local"
    blobs = models / "blobs"
    manifests.mkdir(parents=True)
    blobs.mkdir(parents=True)

    config = b'{"model_format":"gguf"}\n'
    weights = b"synthetic-gguf-weights"
    config_digest = "sha256:" + _sha(config)
    weights_digest = "sha256:" + _sha(weights)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": config_digest,
            "size": len(config),
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": weights_digest,
                "size": len(weights),
            }
        ],
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
    (manifests / "latest").write_bytes(manifest_bytes)
    (blobs / config_digest.replace(":", "-")).write_bytes(config)
    (blobs / weights_digest.replace(":", "-")).write_bytes(weights)
    return models, manifest_bytes, weights


def _contract(manifest_bytes: bytes) -> OllamaArtifactContract:
    return OllamaArtifactContract(
        model_id=_MODEL_ID,
        expected_manifest_digest="sha256:" + _sha(manifest_bytes),
        require_local=True,
    )


def test_stage_copies_only_referenced_verified_manifest_and_blobs(tmp_path: Path) -> None:
    source, manifest_bytes, weights = _source_store(tmp_path)
    unreferenced = source / "blobs" / ("sha256-" + "f" * 64)
    unreferenced.write_bytes(b"must-not-be-staged")
    supervisor = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "staging",
    )

    prepared = supervisor.stage(
        contract=_contract(manifest_bytes),
        manifest_relative_path=_MANIFEST_RELATIVE,
    )

    staged_manifest = prepared.models_path / "manifests" / Path(_MANIFEST_RELATIVE)
    assert staged_manifest.read_bytes() == manifest_bytes
    assert prepared.identity.referenced_blob_count == 2
    assert prepared.identity.referenced_blob_bytes > len(weights)
    assert not (prepared.models_path / "blobs" / unreferenced.name).exists()
    assert prepared.identity.manifest_digest == "sha256:" + _sha(manifest_bytes)
    assert len(prepared.identity.identity_sha256) == 64


def test_existing_content_addressed_stage_is_reverified_and_reused(tmp_path: Path) -> None:
    source, manifest_bytes, _ = _source_store(tmp_path)
    supervisor = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "staging",
    )
    first = supervisor.stage(
        contract=_contract(manifest_bytes),
        manifest_relative_path=_MANIFEST_RELATIVE,
    )
    second = supervisor.stage(
        contract=_contract(manifest_bytes),
        manifest_relative_path=_MANIFEST_RELATIVE,
    )

    assert second.models_path == first.models_path
    assert second.identity == first.identity


def test_source_manifest_digest_mismatch_is_rejected_before_staging(tmp_path: Path) -> None:
    source, manifest_bytes, _ = _source_store(tmp_path)
    supervisor = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "staging",
    )
    wrong = OllamaArtifactContract(
        model_id=_MODEL_ID,
        expected_manifest_digest="sha256:" + "f" * 64,
        require_local=True,
    )

    with pytest.raises(ValueError, match="manifest digest"):
        supervisor.stage(
            contract=wrong,
            manifest_relative_path=_MANIFEST_RELATIVE,
        )

    assert not any(
        entry.name.startswith("sha256-")
        for entry in supervisor.staging_root.iterdir()
    )
    assert manifest_bytes


def test_blob_content_or_size_drift_is_rejected(tmp_path: Path) -> None:
    source, manifest_bytes, _ = _source_store(tmp_path)
    blob_paths = sorted((source / "blobs").iterdir())
    blob_paths[-1].write_bytes(b"tampered")
    supervisor = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "staging",
    )

    with pytest.raises(ValueError, match="blob (size|digest)"):
        supervisor.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_tampered_existing_stage_fails_closed(tmp_path: Path) -> None:
    source, manifest_bytes, _ = _source_store(tmp_path)
    supervisor = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "staging",
    )
    prepared = supervisor.stage(
        contract=_contract(manifest_bytes),
        manifest_relative_path=_MANIFEST_RELATIVE,
    )
    staged_blob = next((prepared.models_path / "blobs").iterdir())
    staged_blob.write_bytes(b"tampered-stage")

    with pytest.raises((RuntimeError, ValueError)):
        supervisor.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_manifest_path_traversal_and_unowned_stage_root_are_rejected(tmp_path: Path) -> None:
    source, manifest_bytes, _ = _source_store(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    sentinel = staging / "operator-data.txt"
    sentinel.write_text("keep\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="lacks laboratory ownership marker"):
        OllamaModelStagingSupervisor(
            source_models_root=source,
            staging_root=staging,
        )
    assert sentinel.read_text(encoding="utf-8") == "keep\n"

    clean = OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "clean-staging",
    )
    with pytest.raises(ValueError, match="relative path"):
        clean.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path="../escape/latest",
        )
