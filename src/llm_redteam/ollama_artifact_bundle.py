"""Stage one exact Ollama model into a minimal read-only-mountable model store.

The full host Ollama cache is never required as Blue input. A bundle contains exactly one
manifest and only the content-addressed blobs referenced by that manifest. Source and
staged bytes are verified by SHA-256 and declared size before the bundle is admitted.

The bundle directory is trusted control-plane state. Files are copied rather than hard-
linked so later mutation of the ordinary Ollama cache cannot silently change a staged
artifact. Container read-only mounting is a separate runtime enforcement step.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from hashlib import sha256
from pathlib import Path, PurePosixPath

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_artifact import ModelArtifactIdentity

_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
_CHUNK_SIZE = 1024 * 1024


class OllamaBundleBlob(StrictModel):
    """One unique content-addressed file required by an Ollama manifest."""

    digest: str = Field(pattern=_SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    media_types: tuple[str, ...] = Field(min_length=1)

    @property
    def relative_path(self) -> str:
        return "blobs/" + self.digest.replace(":", "-")


class OllamaArtifactBundleContract(StrictModel):
    """Stable minimal filesystem view for one verified local Ollama artifact."""

    version: int = Field(ge=1, default=1)
    provider_id: str = Field(default="ollama")
    model_id: str = Field(min_length=1, max_length=256)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_size_bytes: int = Field(ge=0)
    manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    manifest_relative_path: str = Field(min_length=1, max_length=1024)
    blobs: tuple[OllamaBundleBlob, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def bundle_contract_is_safe(self) -> OllamaArtifactBundleContract:
        _validate_manifest_relative_path(self.manifest_relative_path)
        digests = [blob.digest for blob in self.blobs]
        if len(digests) != len(set(digests)):
            raise ValueError("Ollama artifact bundle blob digests must be unique")
        return self

    @property
    def manifest_store_path(self) -> str:
        return "manifests/" + self.manifest_relative_path

    @property
    def bundle_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class OllamaArtifactBundleVerification(StrictModel):
    """Hash-only evidence that one filesystem bundle matches its stable contract."""

    contract_sha256: str = Field(pattern=_HASH_PATTERN)
    manifest_sha256: str = Field(pattern=_HASH_PATTERN)
    blob_inventory_sha256: str = Field(pattern=_HASH_PATTERN)
    blob_count: int = Field(ge=1)
    total_blob_bytes: int = Field(ge=0)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def build_ollama_artifact_bundle_contract(
    *,
    artifact: ModelArtifactIdentity,
    manifest_bytes: bytes,
    manifest_relative_path: str,
) -> OllamaArtifactBundleContract:
    """Parse and bind one local Ollama manifest to the previously verified artifact."""

    if artifact.provider_id != "ollama":
        raise ValueError("Ollama artifact bundle requires provider_id=ollama")
    if not artifact.local_artifact:
        raise ValueError("Ollama artifact bundle requires a local model artifact")
    _validate_manifest_relative_path(manifest_relative_path)

    manifest_hash = "sha256:" + sha256(manifest_bytes).hexdigest()
    if manifest_hash != artifact.artifact_digest:
        raise ValueError("Ollama manifest bytes do not match the artifact manifest digest")

    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Ollama manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise ValueError("Ollama manifest must be a JSON object")
    if manifest.get("schemaVersion") != 2:
        raise ValueError("Ollama artifact bundle requires manifest schemaVersion=2")

    members: list[dict[str, object]] = []
    config = manifest.get("config")
    if not isinstance(config, dict):
        raise ValueError("Ollama manifest config must be an object")
    members.append(config)
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        raise ValueError("Ollama manifest layers must be a list")
    for layer in layers:
        if not isinstance(layer, dict):
            raise ValueError("Ollama manifest layer must be an object")
        members.append(layer)

    aggregated: dict[str, tuple[int, set[str]]] = {}
    referenced_size_bytes = 0
    for member in members:
        digest = _canonical_digest(member.get("digest"))
        size = member.get("size")
        media_type = member.get("mediaType")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("Ollama manifest member size must be a non-negative integer")
        if not isinstance(media_type, str) or not media_type:
            raise ValueError("Ollama manifest member mediaType must be a non-empty string")
        referenced_size_bytes += size
        existing = aggregated.get(digest)
        if existing is None:
            aggregated[digest] = (size, {media_type})
        else:
            existing_size, media_types = existing
            if existing_size != size:
                raise ValueError("duplicate Ollama blob digest has conflicting sizes")
            media_types.add(media_type)

    blobs = tuple(
        OllamaBundleBlob(
            digest=digest,
            size_bytes=size,
            media_types=tuple(sorted(media_types)),
        )
        for digest, (size, media_types) in sorted(aggregated.items())
    )
    if not blobs:
        raise ValueError("Ollama artifact manifest references no blobs")
    if referenced_size_bytes != artifact.artifact_size_bytes:
        raise ValueError(
            "Ollama manifest referenced bytes do not match artifact inventory size"
        )

    return OllamaArtifactBundleContract(
        model_id=artifact.model_id,
        artifact_identity_sha256=artifact.identity_sha256,
        artifact_size_bytes=artifact.artifact_size_bytes,
        manifest_digest=artifact.artifact_digest,
        manifest_relative_path=manifest_relative_path,
        blobs=blobs,
    )


def verify_ollama_artifact_bundle(
    *,
    models_root: Path,
    contract: OllamaArtifactBundleContract,
) -> OllamaArtifactBundleVerification:
    """Verify exact manifest and all referenced blobs under one Ollama models root."""

    root = models_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Ollama models root must be a directory")

    manifest_path = _resolve_contained(
        root,
        PurePosixPath(contract.manifest_store_path),
    )
    manifest_sha = _verify_file(
        manifest_path,
        expected_digest=contract.manifest_digest,
        expected_size=None,
    )

    inventory: list[dict[str, object]] = []
    total_bytes = 0
    for blob in contract.blobs:
        path = _resolve_contained(root, PurePosixPath(blob.relative_path))
        digest = _verify_file(
            path,
            expected_digest=blob.digest,
            expected_size=blob.size_bytes,
        )
        inventory.append(
            {
                "digest": "sha256:" + digest,
                "size_bytes": blob.size_bytes,
                "media_types": list(blob.media_types),
            }
        )
        total_bytes += blob.size_bytes

    return OllamaArtifactBundleVerification(
        contract_sha256=contract.bundle_sha256,
        manifest_sha256=manifest_sha,
        blob_inventory_sha256=canonical_json_hash(inventory),
        blob_count=len(contract.blobs),
        total_blob_bytes=total_bytes,
    )


def stage_ollama_artifact_bundle(
    *,
    source_models_root: Path,
    destination_models_root: Path,
    contract: OllamaArtifactBundleContract,
) -> OllamaArtifactBundleVerification:
    """Copy an exact minimal store and verify destination bytes before atomic admission."""

    source_verification = verify_ollama_artifact_bundle(
        models_root=source_models_root,
        contract=contract,
    )
    destination = destination_models_root.absolute()
    if destination.exists():
        raise FileExistsError("Ollama artifact bundle destination must not already exist")
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)

    staging = Path(tempfile.mkdtemp(prefix=".ollama-bundle-", dir=parent))
    try:
        manifest_source = _resolve_contained(
            source_models_root.resolve(strict=True),
            PurePosixPath(contract.manifest_store_path),
        )
        manifest_destination = staging / Path(contract.manifest_store_path)
        manifest_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(manifest_source, manifest_destination)

        for blob in contract.blobs:
            source = _resolve_contained(
                source_models_root.resolve(strict=True),
                PurePosixPath(blob.relative_path),
            )
            target = staging / Path(blob.relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        staged_verification = verify_ollama_artifact_bundle(
            models_root=staging,
            contract=contract,
        )
        if staged_verification != source_verification:
            raise RuntimeError("staged Ollama artifact verification differs from source")
        staging.replace(destination)
        return staged_verification
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_manifest_relative_path(value: str) -> None:
    if "\\" in value or "\x00" in value:
        raise ValueError("Ollama manifest relative path must use safe POSIX separators")
    raw_parts = value.split("/")
    if len(raw_parts) != 4 or any(
        part in {"", ".", ".."} for part in raw_parts
    ):
        raise ValueError("Ollama manifest relative path must have four safe components")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ValueError("Ollama manifest relative path must remain inside manifests")


def _canonical_digest(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Ollama manifest member digest must be a string")
    normalized = value.strip().casefold()
    if normalized.startswith("sha256:"):
        hexadecimal = normalized[7:]
    else:
        raise ValueError("Ollama manifest member digest must use sha256: prefix")
    if len(hexadecimal) != 64 or any(
        character not in "0123456789abcdef" for character in hexadecimal
    ):
        raise ValueError("Ollama manifest member digest must be exact SHA-256")
    return "sha256:" + hexadecimal


def _resolve_contained(root: Path, relative: PurePosixPath) -> Path:
    candidate = root.joinpath(*relative.parts).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Ollama artifact path escapes the models root") from exc
    if not candidate.is_file():
        raise ValueError("Ollama artifact member must be a regular file")
    return candidate


def _verify_file(
    path: Path,
    *,
    expected_digest: str,
    expected_size: int | None,
) -> str:
    if expected_size is not None and path.stat().st_size != expected_size:
        raise ValueError("Ollama artifact member size does not match manifest")
    digest = sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    hexadecimal = digest.hexdigest()
    if "sha256:" + hexadecimal != expected_digest:
        raise ValueError("Ollama artifact member SHA-256 does not match manifest")
    return hexadecimal
