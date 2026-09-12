import json
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.ollama_artifact_bundle import (
    OllamaArtifactBundleContract,
    build_ollama_artifact_bundle_contract,
    stage_ollama_artifact_bundle,
    verify_ollama_artifact_bundle,
)

_MANIFEST_RELATIVE = "registry.ollama.ai/library/qwen-test/latest"


def _digest(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def _write_blob(root: Path, data: bytes) -> tuple[str, int]:
    digest = _digest(data)
    path = root / "blobs" / digest.replace(":", "-")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest, len(data)


def _source_store(tmp_path: Path) -> tuple[Path, bytes, ModelArtifactIdentity]:
    root = tmp_path / "source-models"
    config_digest, config_size = _write_blob(root, b'{"architecture":"synthetic"}')
    model_digest, model_size = _write_blob(root, b"synthetic-model-bytes")
    template_digest, template_size = _write_blob(root, b"{{ .Prompt }}")

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": model_digest,
                "size": model_size,
            },
            {
                "mediaType": "application/vnd.ollama.image.template",
                "digest": template_digest,
                "size": template_size,
            },
        ],
    }
    manifest_bytes = (
        json.dumps(manifest, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()
    manifest_path = root / "manifests" / Path(_MANIFEST_RELATIVE)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest_bytes)

    artifact = ModelArtifactIdentity(
        provider_id="ollama",
        model_id="qwen-test:latest",
        artifact_digest=_digest(manifest_bytes),
        artifact_size_bytes=config_size + model_size + template_size,
        local_artifact=True,
        format="gguf",
        family="qwen",
    )
    return root, manifest_bytes, artifact


def _contract(tmp_path: Path) -> tuple[Path, OllamaArtifactBundleContract]:
    root, manifest_bytes, artifact = _source_store(tmp_path)
    contract = build_ollama_artifact_bundle_contract(
        artifact=artifact,
        manifest_bytes=manifest_bytes,
        manifest_relative_path=_MANIFEST_RELATIVE,
    )
    return root, contract


def test_contract_binds_exact_manifest_and_referenced_blobs(tmp_path: Path) -> None:
    root, contract = _contract(tmp_path)

    verification = verify_ollama_artifact_bundle(
        models_root=root,
        contract=contract,
    )

    assert contract.provider_id == "ollama"
    assert contract.model_id == "qwen-test:latest"
    assert contract.manifest_store_path == "manifests/" + _MANIFEST_RELATIVE
    assert len(contract.blobs) == 3
    assert verification.contract_sha256 == contract.bundle_sha256
    assert verification.blob_count == 3
    assert verification.total_blob_bytes > 0
    assert len(verification.proof_sha256) == 64


def test_same_name_wrong_manifest_bytes_fail_closed(tmp_path: Path) -> None:
    _, manifest_bytes, artifact = _source_store(tmp_path)

    with pytest.raises(ValueError, match="manifest digest"):
        build_ollama_artifact_bundle_contract(
            artifact=artifact,
            manifest_bytes=manifest_bytes + b" ",
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_manifest_size_must_match_verified_inventory_size(tmp_path: Path) -> None:
    _, manifest_bytes, artifact = _source_store(tmp_path)
    wrong_size = artifact.model_copy(
        update={"artifact_size_bytes": artifact.artifact_size_bytes + 1}
    )

    with pytest.raises(ValueError, match="inventory size"):
        build_ollama_artifact_bundle_contract(
            artifact=wrong_size,
            manifest_bytes=manifest_bytes,
            manifest_relative_path=_MANIFEST_RELATIVE,
        )


def test_tampered_blob_fails_verification(tmp_path: Path) -> None:
    root, contract = _contract(tmp_path)
    victim = root / Path(contract.blobs[0].relative_path)
    victim.write_bytes(b"tampered")

    with pytest.raises(ValueError, match="size|SHA-256"):
        verify_ollama_artifact_bundle(models_root=root, contract=contract)


def test_staging_copies_only_manifest_and_referenced_blobs(tmp_path: Path) -> None:
    root, contract = _contract(tmp_path)
    extra = root / "blobs" / ("sha256-" + "f" * 64)
    extra.write_bytes(b"unrelated-model")
    unrelated_manifest = root / "manifests" / "registry.ollama.ai/library/other/latest"
    unrelated_manifest.parent.mkdir(parents=True, exist_ok=True)
    unrelated_manifest.write_text("{}\n", encoding="utf-8")

    destination = tmp_path / "staged-models"
    verification = stage_ollama_artifact_bundle(
        source_models_root=root,
        destination_models_root=destination,
        contract=contract,
    )

    assert verification.contract_sha256 == contract.bundle_sha256
    assert (destination / "manifests" / Path(_MANIFEST_RELATIVE)).is_file()
    for blob in contract.blobs:
        assert (destination / Path(blob.relative_path)).is_file()
    assert not (destination / extra.relative_to(root)).exists()
    assert not (destination / unrelated_manifest.relative_to(root)).exists()


def test_staged_bundle_is_independent_from_source_mutation(tmp_path: Path) -> None:
    root, contract = _contract(tmp_path)
    destination = tmp_path / "staged-models"
    expected = stage_ollama_artifact_bundle(
        source_models_root=root,
        destination_models_root=destination,
        contract=contract,
    )

    source_blob = root / Path(contract.blobs[0].relative_path)
    source_blob.write_bytes(b"changed-after-staging")

    observed = verify_ollama_artifact_bundle(
        models_root=destination,
        contract=contract,
    )
    assert observed == expected


def test_destination_must_be_new(tmp_path: Path) -> None:
    root, contract = _contract(tmp_path)
    destination = tmp_path / "already-exists"
    destination.mkdir()

    with pytest.raises(FileExistsError, match="must not already exist"):
        stage_ollama_artifact_bundle(
            source_models_root=root,
            destination_models_root=destination,
            contract=contract,
        )


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "../outside",
        "/absolute/manifest/path",
        "registry.ollama.ai/library/../latest",
        "registry.ollama.ai\\library\\model\\latest",
    ),
)
def test_manifest_path_traversal_is_rejected(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    _, manifest_bytes, artifact = _source_store(tmp_path)

    with pytest.raises(ValueError, match="relative path"):
        build_ollama_artifact_bundle_contract(
            artifact=artifact,
            manifest_bytes=manifest_bytes,
            manifest_relative_path=unsafe_path,
        )
