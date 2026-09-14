"""Content-addressed staging of one verified local Ollama model artifact.

A model-service container must not receive the operator's mutable Ollama cache. This
supervisor copies exactly one manifest and only the config/layer blobs referenced by it
into an evaluator-owned content-addressed store. Every copied object is verified by
SHA-256 and declared size before the stage is admitted for a read-only Docker mount.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .ollama_artifact import OllamaArtifactContract

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_OWNERSHIP_MARKER = ".llm-redteam-ollama-stage-root-v1"
_OWNERSHIP_CONTENT = "llm-redteam-lab verified Ollama staging root v1\n"


class OllamaStagedModelStoreIdentity(StrictModel):
    """Persistence-safe identity of one complete staged Ollama model store."""

    version: int = Field(ge=1, default=1)
    model_id: str = Field(min_length=1)
    manifest_digest: str = Field(min_length=1)
    manifest_relative_path_sha256: str = Field(pattern=_HASH_PATTERN)
    staged_tree_sha256: str = Field(pattern=_HASH_PATTERN)
    referenced_blob_count: int = Field(ge=1)
    referenced_blob_bytes: int = Field(ge=0)

    @property
    def identity_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


@dataclass(frozen=True, slots=True)
class PreparedOllamaModelStore:
    """Ephemeral host path plus stable verified stage identity."""

    models_path: Path
    identity: OllamaStagedModelStoreIdentity


class OllamaModelStagingSupervisor:
    """Create or verify a content-addressed local model store for one Ollama artifact."""

    def __init__(
        self,
        *,
        source_models_root: str | Path,
        staging_root: str | Path,
    ) -> None:
        self.source_models_root = Path(source_models_root).resolve(strict=False)
        self.staging_root = Path(staging_root).resolve(strict=False)
        if not self.source_models_root.is_dir():
            raise ValueError("source Ollama models root is not a directory")
        if not (self.source_models_root / "manifests").is_dir():
            raise ValueError("source Ollama models root lacks manifests directory")
        if not (self.source_models_root / "blobs").is_dir():
            raise ValueError("source Ollama models root lacks blobs directory")
        self._ensure_owned_root()

    def stage(
        self,
        *,
        contract: OllamaArtifactContract,
        manifest_relative_path: str,
    ) -> PreparedOllamaModelStore:
        """Stage exactly the manifest and blobs needed by the predeclared artifact."""

        self._assert_ownership_marker()
        relative = _safe_manifest_relative_path(manifest_relative_path)
        source_manifest = _resolve_member(
            self.source_models_root / "manifests",
            relative,
            kind="manifest",
        )
        manifest_bytes = source_manifest.read_bytes()
        observed_manifest_digest = "sha256:" + sha256(manifest_bytes).hexdigest()
        if observed_manifest_digest != contract.manifest_digest:
            raise ValueError("source Ollama manifest digest does not match artifact contract")
        try:
            manifest = json.loads(manifest_bytes)
        except json.JSONDecodeError as exc:
            raise ValueError("source Ollama manifest is not valid JSON") from exc
        blob_specs = _manifest_blob_specs(manifest)

        digest_hex = contract.manifest_digest.removeprefix("sha256:")
        stage_root = self.staging_root / ("sha256-" + digest_hex)
        models_path = stage_root / "models"
        identity_path = stage_root / "stage-identity.json"
        if stage_root.exists():
            return self._verify_existing_stage(
                stage_root=stage_root,
                models_path=models_path,
                identity_path=identity_path,
                contract=contract,
                relative=relative,
                blob_specs=blob_specs,
                manifest_bytes=manifest_bytes,
            )

        temporary = self.staging_root / (".building-sha256-" + digest_hex)
        if temporary.exists():
            raise RuntimeError("Ollama staging temporary path already exists")
        try:
            temporary_models = temporary / "models"
            destination_manifest = temporary_models / "manifests" / Path(*relative.parts)
            destination_manifest.parent.mkdir(parents=True, exist_ok=True)
            destination_manifest.write_bytes(manifest_bytes)
            blobs_dir = temporary_models / "blobs"
            blobs_dir.mkdir(parents=True, exist_ok=True)
            total_bytes = 0
            for digest, expected_size in blob_specs:
                source_blob = _source_blob_path(self.source_models_root, digest)
                _verify_blob(source_blob, digest=digest, expected_size=expected_size)
                destination = blobs_dir / digest.replace(":", "-")
                shutil.copyfile(source_blob, destination)
                _verify_blob(destination, digest=digest, expected_size=expected_size)
                total_bytes += expected_size

            staged_tree_sha256 = _tree_sha256(temporary_models)
            identity = OllamaStagedModelStoreIdentity(
                model_id=contract.model_id,
                manifest_digest=contract.manifest_digest,
                manifest_relative_path_sha256=sha256(relative.as_posix().encode()).hexdigest(),
                staged_tree_sha256=staged_tree_sha256,
                referenced_blob_count=len(blob_specs),
                referenced_blob_bytes=total_bytes,
            )
            (temporary / "stage-identity.json").write_text(
                identity.model_dump_json(indent=2) + "\n",
                encoding="utf-8",
            )
            temporary.rename(stage_root)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
            raise

        return PreparedOllamaModelStore(models_path=models_path, identity=identity)

    def _verify_existing_stage(
        self,
        *,
        stage_root: Path,
        models_path: Path,
        identity_path: Path,
        contract: OllamaArtifactContract,
        relative: PurePosixPath,
        blob_specs: tuple[tuple[str, int], ...],
        manifest_bytes: bytes,
    ) -> PreparedOllamaModelStore:
        if not stage_root.is_dir() or not models_path.is_dir() or not identity_path.is_file():
            raise RuntimeError("existing Ollama artifact stage is incomplete")
        try:
            identity = OllamaStagedModelStoreIdentity.model_validate_json(
                identity_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise RuntimeError("existing Ollama stage identity is invalid") from exc
        if identity.model_id != contract.model_id:
            raise RuntimeError("existing Ollama stage model identity changed")
        if identity.manifest_digest != contract.manifest_digest:
            raise RuntimeError("existing Ollama stage manifest identity changed")
        if identity.manifest_relative_path_sha256 != sha256(
            relative.as_posix().encode()
        ).hexdigest():
            raise RuntimeError("existing Ollama stage manifest path changed")

        staged_manifest = models_path / "manifests" / Path(*relative.parts)
        if not staged_manifest.is_file() or staged_manifest.read_bytes() != manifest_bytes:
            raise RuntimeError("existing Ollama stage manifest content changed")
        total_bytes = 0
        for digest, expected_size in blob_specs:
            staged_blob = models_path / "blobs" / digest.replace(":", "-")
            _verify_blob(staged_blob, digest=digest, expected_size=expected_size)
            total_bytes += expected_size
        if identity.referenced_blob_count != len(blob_specs):
            raise RuntimeError("existing Ollama stage blob count changed")
        if identity.referenced_blob_bytes != total_bytes:
            raise RuntimeError("existing Ollama stage blob byte count changed")
        if identity.staged_tree_sha256 != _tree_sha256(models_path):
            raise RuntimeError("existing Ollama stage tree hash changed")
        return PreparedOllamaModelStore(models_path=models_path, identity=identity)

    def _ensure_owned_root(self) -> None:
        if self.staging_root.exists() and not self.staging_root.is_dir():
            raise ValueError("Ollama staging_root must be a directory")
        self.staging_root.mkdir(parents=True, exist_ok=True)
        marker = self.staging_root / _OWNERSHIP_MARKER
        entries = [entry for entry in self.staging_root.iterdir() if entry != marker]
        if marker.exists():
            self._assert_ownership_marker()
            for entry in entries:
                if not entry.is_dir() or not entry.name.startswith("sha256-"):
                    raise RuntimeError("owned Ollama staging root contains an unknown entry")
            return
        if entries:
            raise RuntimeError("non-empty Ollama staging root lacks laboratory ownership marker")
        marker.write_text(_OWNERSHIP_CONTENT, encoding="utf-8")

    def _assert_ownership_marker(self) -> None:
        marker = self.staging_root / _OWNERSHIP_MARKER
        try:
            content = marker.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("Ollama staging ownership marker is missing") from exc
        if content != _OWNERSHIP_CONTENT:
            raise RuntimeError("Ollama staging ownership marker is invalid")


def _safe_manifest_relative_path(value: str) -> PurePosixPath:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise ValueError("Ollama manifest path must be a non-empty relative path")
    return path


def _resolve_member(root: Path, relative: PurePosixPath, *, kind: str) -> Path:
    path = (root / Path(*relative.parts)).resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if not path.is_relative_to(resolved_root):
        raise ValueError(f"Ollama {kind} path escaped models root")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Ollama {kind} must be a regular non-symlink file")
    return path


def _manifest_blob_specs(payload: object) -> tuple[tuple[str, int], ...]:
    if not isinstance(payload, dict):
        raise ValueError("Ollama manifest must be a JSON object")
    values: list[object] = []
    config = payload.get("config")
    if config is not None:
        values.append(config)
    layers = payload.get("layers")
    if not isinstance(layers, list):
        raise ValueError("Ollama manifest must contain a layers list")
    values.extend(layers)

    specs: list[tuple[str, int]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("Ollama manifest layer must be a JSON object")
        digest = value.get("digest")
        size = value.get("size")
        if not isinstance(digest, str) or not _valid_digest(digest):
            raise ValueError("Ollama manifest layer has invalid SHA-256 digest")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("Ollama manifest layer has invalid size")
        if digest in seen:
            continue
        seen.add(digest)
        specs.append((digest, size))
    if not specs:
        raise ValueError("Ollama manifest does not reference any blobs")
    return tuple(specs)


def _source_blob_path(models_root: Path, digest: str) -> Path:
    name = digest.replace(":", "-")
    return _resolve_member(
        models_root / "blobs",
        PurePosixPath(name),
        kind="blob",
    )


def _verify_blob(path: Path, *, digest: str, expected_size: int) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Ollama blob must be a regular non-symlink file")
    stat = path.stat()
    if stat.st_size != expected_size:
        raise ValueError("Ollama blob size does not match manifest")
    observed = "sha256:" + _file_sha256(path)
    if observed != digest:
        raise ValueError("Ollama blob digest does not match manifest")


def _valid_digest(value: str) -> bool:
    if not value.startswith("sha256:") or len(value) != 71:
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    if not root.is_dir():
        raise ValueError("Ollama staged models root must be a directory")
    rows: list[dict[str, str | int]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError("Ollama staged model store forbids symlinks")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            rows.append({"path": relative + "/", "kind": "directory"})
        elif path.is_file():
            rows.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size": path.stat().st_size,
                    "sha256": _file_sha256(path),
                }
            )
        else:
            raise ValueError("Ollama staged store contains unsupported filesystem entry")
    return canonical_json_hash(rows)
