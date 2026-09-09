"""Hash-addressed image artifacts for multimodal security evaluation.

Normal experiment persistence stores artifact metadata and references, not raw image
bytes. Raw generated images are resolved through an explicit artifact store only
when a visual verifier requires them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field

from .domain import StrictModel


class ImageArtifact(StrictModel):
    schema_version: int = Field(ge=1, default=1)
    artifact_id: str = Field(min_length=1)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mime_type: Literal["image/png", "image/jpeg", "image/webp"]
    width: int = Field(gt=0)
    height: int = Field(gt=0)
    seed: int | None = None
    storage_ref: str = Field(min_length=1)
    sensitive: Literal[True] = True
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)


class ImageArtifactStorePolicy(StrictModel):
    allow_sensitive_artifacts: bool = False
    overwrite: bool = False


@runtime_checkable
class ImageArtifactStore(Protocol):
    """Resolve generated image bytes without putting them in normal SQL evidence."""

    def put(
        self,
        data: bytes,
        *,
        mime_type: str,
        width: int,
        height: int,
        seed: int | None = None,
        metadata: dict[str, str | int | float | bool] | None = None,
    ) -> ImageArtifact: ...

    def get(self, artifact_id: str) -> tuple[ImageArtifact, bytes]: ...


class InMemoryImageArtifactStore:
    """Deterministic zero-I/O artifact store for tests and smoke orchestration."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[ImageArtifact, bytes]] = {}

    def put(
        self,
        data: bytes,
        *,
        mime_type: str,
        width: int,
        height: int,
        seed: int | None = None,
        metadata: dict[str, str | int | float | bool] | None = None,
    ) -> ImageArtifact:
        artifact = _build_artifact(
            data,
            mime_type=mime_type,
            width=width,
            height=height,
            seed=seed,
            storage_ref="memory",
            metadata=metadata,
        )
        self._items[artifact.artifact_id] = (artifact, bytes(data))
        return artifact

    def get(self, artifact_id: str) -> tuple[ImageArtifact, bytes]:
        try:
            artifact, data = self._items[artifact_id]
        except KeyError as exc:
            raise FileNotFoundError(f"unknown image artifact: {artifact_id}") from exc
        _verify_content_hash(artifact, data)
        return artifact, bytes(data)


class LocalImageArtifactStore:
    """Explicit opt-in local store for generated visual evidence.

    This is intentionally separate from normal experiment persistence. The store
    writes binary content and a small JSON sidecar under an operator-selected
    directory. Artifact IDs are derived from SHA-256 so tampering is detected on
    read.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        policy: ImageArtifactStorePolicy | None = None,
    ) -> None:
        self.root = Path(root)
        self.policy = policy or ImageArtifactStorePolicy()

    def put(
        self,
        data: bytes,
        *,
        mime_type: str,
        width: int,
        height: int,
        seed: int | None = None,
        metadata: dict[str, str | int | float | bool] | None = None,
    ) -> ImageArtifact:
        if not self.policy.allow_sensitive_artifacts:
            raise PermissionError("sensitive image artifact storage is disabled")

        suffix = _suffix_for_mime(mime_type)
        provisional = _build_artifact(
            data,
            mime_type=mime_type,
            width=width,
            height=height,
            seed=seed,
            storage_ref="pending",
            metadata=metadata,
        )
        self.root.mkdir(parents=True, exist_ok=True)
        image_path = self.root / f"{provisional.artifact_id}{suffix}"
        metadata_path = self.root / f"{provisional.artifact_id}.json"
        if not self.policy.overwrite and (image_path.exists() or metadata_path.exists()):
            raise FileExistsError(f"image artifact already exists: {provisional.artifact_id}")

        artifact = provisional.model_copy(update={"storage_ref": str(image_path)})
        _atomic_write_bytes(image_path, data)
        _atomic_write_text(
            metadata_path,
            json.dumps(artifact.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        )
        _restrict_permissions(image_path)
        _restrict_permissions(metadata_path)
        return artifact

    def get(self, artifact_id: str) -> tuple[ImageArtifact, bytes]:
        metadata_path = self.root / f"{artifact_id}.json"
        try:
            artifact = ImageArtifact.model_validate_json(metadata_path.read_text("utf-8"))
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"unknown image artifact: {artifact_id}") from exc
        if artifact.artifact_id != artifact_id:
            raise ValueError("image artifact metadata ID mismatch")
        image_path = Path(artifact.storage_ref)
        data = image_path.read_bytes()
        _verify_content_hash(artifact, data)
        return artifact, data


def _build_artifact(
    data: bytes,
    *,
    mime_type: str,
    width: int,
    height: int,
    seed: int | None,
    storage_ref: str,
    metadata: dict[str, str | int | float | bool] | None,
) -> ImageArtifact:
    from hashlib import sha256

    digest = sha256(data).hexdigest()
    return ImageArtifact(
        artifact_id=f"image-{digest[:24]}",
        content_hash=digest,
        mime_type=mime_type,
        width=width,
        height=height,
        seed=seed,
        storage_ref=storage_ref,
        metadata=metadata or {},
    )


def _verify_content_hash(artifact: ImageArtifact, data: bytes) -> None:
    from hashlib import sha256

    if sha256(data).hexdigest() != artifact.content_hash:
        raise ValueError(f"image artifact content hash mismatch: {artifact.artifact_id}")


def _suffix_for_mime(mime_type: str) -> str:
    return {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/webp": ".webp",
    }.get(mime_type) or _raise_unsupported_mime(mime_type)


def _raise_unsupported_mime(mime_type: str) -> str:
    raise ValueError(f"unsupported image MIME type: {mime_type}")


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _atomic_write_text(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _restrict_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        # Best effort only on platforms/filesystems that support POSIX-like modes.
        pass
