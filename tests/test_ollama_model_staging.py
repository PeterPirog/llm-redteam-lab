import json
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.ollama_model_staging import (
    OllamaModelStagingSupervisor,
    _tree_sha256,
)

_MODEL_ID = "qwen-local"
_MANIFEST_RELATIVE = "registry.ollama.ai/library/qwen-local/latest"


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _source_store(tmp_path: Path) -> tuple[Path, bytes, bytes, bytes]:
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
        "config": {
            "digest": config_digest,
            "size": len(config),
        },
        "layers": [
            {
                "digest": weights_digest,
                "size": len(weights),
            }
        ],
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
    (manifests / "latest").write_bytes(manifest_bytes)
    (blobs / config_digest.replace(":", "-")).write_bytes(config)
    (blobs / weights_digest.replace(":", "-")).write_bytes(weights)
    return models, manifest_bytes, config, weights


def _contract(manifest_bytes: bytes, *, require_local: bool = True) -> OllamaArtifactContract:
    return OllamaArtifactContract(
        model_id=_MODEL_ID,
        expected_manifest_digest="sha256:" + _sha(manifest_bytes),
        require_local=require_local,
    )


def _supervisor(tmp_path: Path, source: Path) -> OllamaModelStagingSupervisor:
    return OllamaModelStagingSupervisor(
        source_models_root=source,
        staging_root=tmp_path / "staging",
    )


def test_stage_copies_only_referenced_verified_manifest_and_blobs(tmp_path: Path) -> None:
    source, manifest_bytes, config, weights = _source_store(tmp_path)
    unreferenced = source / "blobs" / ("sha256-" + "f" * 64)
    unreferenced.write_bytes(b"must-not-be-staged")
    supervisor = _supervisor(tmp_path, source)

    prepared = supervisor.stage(
        contract=_contract(manifest_bytes),
        manifest_relative_path=_MANIFEST_RELATIVE,
    )

    staged_manifest = prepared.models_path / "manifests" / Path(_MANIFEST_RELATIVE)
    assert staged_manifest.read_bytes() == manifest_bytes
    assert prepared.identity.version == 2
    assert prepared.identity.referenced_blob_count == 2
    assert prepared.identity.referenced_blob_bytes == len(config) + len(weights)
    assert not (prepared.models_path / "blobs" / unreferenced.name).exists()
    assert prepared.identity.manifest_digest == "sha256:" + _sha(manifest_bytes)
    assert len(prepared.identity.identity_sha256) == 64


def test_existing_stage_is_fully_reverified_before_reuse(tmp_path: Path) -> None:
    source, manifest_bytes, _, _ = _source_store(tmp_path)
    supervisor = _supervisor(tmp_path, source)
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


def test_identity_file_cannot_bless_an_extra_staged_file(tmp_path: Path) -> None:
    source, manifest_bytes, _, _ = _source_store(tmp_path)
    supervisor = _supervisor(tmp_path, source)
    prepared = supervisor.stage(
        contract=_contract(manifest_bytes),
        manifest_relative_path=_MANIFEST_RELATIVE,
    )
    extra = prepared.models_path / "blobs" / "attacker-extra"
    extra.write_bytes(b"unexpected")

    identity_path = prepared.models_path.parent / "stage-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["staged_tree_sha256"] = _tree_sha256(prepared.models_path)
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    with pytest.raises(RuntimeError, match="unexpected filesystem entries"):
        supervisor.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_source_manifest_digest_and_blob_drift_are_rejected(tmp_path: Path) -> None:
    source, manifest_bytes, _, _ = _source_store(tmp_path)
    supervisor = _supervisor(tmp_path, source)
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

    blob = sorted((source / "blobs").iterdir())[-1]
    blob.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="blob (size|digest)"):
        supervisor.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_existing_stage_content_tamper_fails_closed(tmp_path: Path) -> None:
    source, manifest_bytes, _, _ = _source_store(tmp_path)
    supervisor = _supervisor(tmp_path, source)
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


def test_path_traversal_unowned_root_and_nonlocal_contract_are_rejected(tmp_path: Path) -> None:
    source, manifest_bytes, _, _ = _source_store(tmp_path)
    staging = tmp_path / "unowned-staging"
    staging.mkdir()
    sentinel = staging / "operator-data.txt"
    sentinel.write_text("keep\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="lacks laboratory ownership marker"):
        OllamaModelStagingSupervisor(
            source_models_root=source,
            staging_root=staging,
        )
    assert sentinel.read_text(encoding="utf-8") == "keep\n"

    supervisor = _supervisor(tmp_path, source)
    for bad_path in ("../escape/latest", "/absolute/latest", "a//b", "a/./b"):
        with pytest.raises(ValueError, match="path"):
            supervisor.stage(
                contract=_contract(manifest_bytes),
                manifest_relative_path=bad_path,
            )
    with pytest.raises(ValueError, match="local-only"):
        supervisor.stage(
            contract=_contract(manifest_bytes, require_local=False),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_source_manifest_symlink_is_rejected(tmp_path: Path) -> None:
    source, manifest_bytes, _, _ = _source_store(tmp_path)
    manifest = source / "manifests" / Path(_MANIFEST_RELATIVE)
    real = manifest.with_name("real-manifest")
    manifest.rename(real)
    try:
        manifest.symlink_to(real.name)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    supervisor = _supervisor(tmp_path, source)
    with pytest.raises(ValueError, match="symlink"):
        supervisor.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_staging_root_symlink_is_rejected(tmp_path: Path) -> None:
    source, _, _, _ = _source_store(tmp_path)
    real = tmp_path / "real-stage"
    real.mkdir()
    link = tmp_path / "stage-link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(ValueError, match="symlink"):
        OllamaModelStagingSupervisor(
            source_models_root=source,
            staging_root=link,
        )


def test_manifest_repeated_digest_with_conflicting_size_is_rejected(tmp_path: Path) -> None:
    source, _, config, _ = _source_store(tmp_path)
    digest = "sha256:" + _sha(config)
    manifest = {
        "config": {"digest": digest, "size": len(config)},
        "layers": [{"digest": digest, "size": len(config) + 1}],
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
    manifest_path = source / "manifests" / Path(_MANIFEST_RELATIVE)
    manifest_path.write_bytes(manifest_bytes)
    supervisor = _supervisor(tmp_path, source)

    with pytest.raises(ValueError, match="conflicting size"):
        supervisor.stage(
            contract=_contract(manifest_bytes),
            manifest_relative_path=_MANIFEST_RELATIVE,
        )
