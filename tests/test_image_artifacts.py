from pathlib import Path

import pytest

from llm_redteam.image_artifacts import (
    ImageArtifactStorePolicy,
    InMemoryImageArtifactStore,
    LocalImageArtifactStore,
)


def test_in_memory_image_artifact_is_hash_addressed() -> None:
    store = InMemoryImageArtifactStore()
    artifact = store.put(
        b"synthetic-image-bytes",
        mime_type="image/png",
        width=32,
        height=24,
        seed=7,
    )

    resolved, data = store.get(artifact.artifact_id)

    assert resolved == artifact
    assert data == b"synthetic-image-bytes"
    assert artifact.artifact_id.startswith("image-")
    assert len(artifact.content_hash) == 64
    assert artifact.sensitive is True


def test_local_image_store_requires_explicit_opt_in_and_detects_tampering(
    tmp_path: Path,
) -> None:
    denied = LocalImageArtifactStore(tmp_path / "denied")
    with pytest.raises(PermissionError):
        denied.put(
            b"synthetic-image",
            mime_type="image/png",
            width=16,
            height=16,
        )

    store = LocalImageArtifactStore(
        tmp_path / "allowed",
        policy=ImageArtifactStorePolicy(allow_sensitive_artifacts=True),
    )
    artifact = store.put(
        b"synthetic-image",
        mime_type="image/png",
        width=16,
        height=16,
    )
    image_path = Path(artifact.storage_ref)
    metadata_path = image_path.with_suffix(".json")

    assert image_path.is_file()
    assert metadata_path.is_file()
    assert "synthetic-image" not in metadata_path.read_text(encoding="utf-8")

    image_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="content hash mismatch"):
        store.get(artifact.artifact_id)
