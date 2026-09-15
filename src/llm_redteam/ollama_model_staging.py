"""Content-addressed staging of one verified local Ollama model artifact.

The evaluator never mounts the operator's mutable Ollama cache into a measurement peer.
Instead, it copies exactly one predeclared manifest and the blobs referenced by that
manifest into a laboratory-owned store. Source and staged content are reverified by size
and SHA-256, symlinks are rejected, and existing stages must contain exactly the expected
filesystem members before they may be reused.
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
_OWNERSHIP_MARKER = ".llm-redteam-ollama-stage-root-v2"
_OWNERSHIP_CONTENT = "llm-redteam-lab verified Ollama staging root v2\n"


class OllamaStagedModelStoreIdentity(StrictModel):
    """Persistence-safe identity of one complete staged Ollama model store."""

    version: int = Field(ge=1, default=2)
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
    """Create or verify a content-addressed local store for one Ollama artifact."""

    def __init__(
        self,
        *,
        source_models_root: str | Path,
        staging_root: str | Path,
    ) -> None:
        self.source_models_root = Path(source_models_root)
        self.staging_root = Path(staging_root)
        _require_directory(self.source_models_root, kind="source Ollama models root")
        _require_directory(
            self.source_models_root / "manifests",
            kind="source Ollama manifests directory",
        )
        _require_directory(
            self.source_models_root / "blobs",
            kind="source Ollama blobs directory",
        )
        self.source_models_root = self.source_models_root.resolve(strict=True)
        self._ensure_owned_root()
        self.staging_root = self.staging_root.resolve(strict=True)

    def stage(
        self,
        *,
        contract: OllamaArtifactContract,
        manifest_relative_path: str,
    ) -> PreparedOllamaModelStore:
        """Stage exactly the declared manifest and every unique referenced blob."""

        if not contract.require_local:
            raise ValueError("Ollama staging requires a local-only artifact contract")
        self._assert_ownership_marker()
        relative = _safe_manifest_relative_path(manifest_relative_path)
        source_manifest = _resolve_regular_member(
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
        if stage_root.exists() or stage_root.is_symlink():
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
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError("Ollama staging temporary path already exists")
        temporary.mkdir(mode=0o700)
        try:
            temporary_models = temporary / "models"
            destination_manifest = temporary_models / "manifests" / Path(*relative.parts)
            destination_manifest.parent.mkdir(parents=True)
            destination_manifest.write_bytes(manifest_bytes)
            blobs_dir = temporary_models / "blobs"
            blobs_dir.mkdir(parents=True)
            for digest, expected_size in blob_specs:
                source_blob = _source_blob_path(self.source_models_root, digest)
                _verify_blob(source_blob, digest=digest, expected_size=expected_size)
                destination = blobs_dir / digest.replace(":", "-")
                shutil.copyfile(source_blob, destination)
                _verify_blob(destination, digest=digest, expected_size=expected_size)

            _verify_exact_stage_members(
                temporary_models,
                manifest_relative_path=relative,
                blob_specs=blob_specs,
            )
            identity = _build_identity(
                models_path=temporary_models,
                contract=contract,
                relative=relative,
                blob_specs=blob_specs,
            )
            (temporary / "stage-identity.json").write_text(
                identity.model_dump_json(indent=2) + "\n",
                encoding="utf-8",
            )
            temporary.rename(stage_root)
        except Exception:
            if temporary.exists() and not temporary.is_symlink():
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
        _require_directory(stage_root, kind="existing Ollama artifact stage")
        _require_directory(models_path, kind="existing staged Ollama models root")
        _require_regular_file(identity_path, kind="existing Ollama stage identity")
        try:
            stored_identity = OllamaStagedModelStoreIdentity.model_validate_json(
                identity_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise RuntimeError("existing Ollama stage identity is invalid") from exc

        staged_manifest = _resolve_regular_member(
            models_path / "manifests",
            relative,
            kind="staged manifest",
        )
        if staged_manifest.read_bytes() != manifest_bytes:
            raise RuntimeError("existing Ollama stage manifest content changed")
        for digest, expected_size in blob_specs:
            staged_blob = _resolve_regular_member(
                models_path / "blobs",
                PurePosixPath(digest.replace(":", "-")),
                kind="staged blob",
            )
            _verify_blob(staged_blob, digest=digest, expected_size=expected_size)

        _verify_exact_stage_members(
            models_path,
            manifest_relative_path=relative,
            blob_specs=blob_specs,
        )
        expected_identity = _build_identity(
            models_path=models_path,
            contract=contract,
            relative=relative,
            blob_specs=blob_specs,
        )
        if stored_identity != expected_identity:
            raise RuntimeError("existing Ollama stage identity does not match verified content")
        return PreparedOllamaModelStore(models_path=models_path, identity=expected_identity)

    def _ensure_owned_root(self) -> None:
        if self.staging_root.exists() or self.staging_root.is_symlink():
            _require_directory(self.staging_root, kind="Ollama staging root")
        else:
            self.staging_root.mkdir(parents=True, mode=0o700)
            _require_directory(self.staging_root, kind="Ollama staging root")
        marker = self.staging_root / _OWNERSHIP_MARKER
        entries = [entry for entry in self.staging_root.iterdir() if entry != marker]
        if marker.exists() or marker.is_symlink():
            self._assert_ownership_marker()
            for entry in entries:
                if entry.is_symlink() or not entry.is_dir() or not entry.name.startswith("sha256-"):
                    raise RuntimeError("owned Ollama staging root contains an unknown entry")
            return
        if entries:
            raise RuntimeError("non-empty Ollama staging root lacks laboratory ownership marker")
        marker.write_text(_OWNERSHIP_CONTENT, encoding="utf-8")
        _require_regular_file(marker, kind="Ollama staging ownership marker")

    def _assert_ownership_marker(self) -> None:
        marker = self.staging_root / _OWNERSHIP_MARKER
        _require_regular_file(marker, kind="Ollama staging ownership marker")
        try:
            content = marker.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("Ollama staging ownership marker is unreadable") from exc
        if content != _OWNERSHIP_CONTENT:
            raise RuntimeError("Ollama staging ownership marker is invalid")


def _safe_manifest_relative_path(value: str) -> PurePosixPath:
    if not value or "\x00" in value:
        raise ValueError("Ollama manifest path must be a non-empty relative path")
    normalized = value.replace("\\", "/")
    raw_parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("Ollama manifest path must be canonical and relative")
    path = PurePosixPath(*raw_parts)
    if path.is_absolute():
        raise ValueError("Ollama manifest path must be a non-empty relative path")
    return path


def _resolve_regular_member(root: Path, relative: PurePosixPath, *, kind: str) -> Path:
    _require_directory(root, kind=f"Ollama {kind} root")
    root_resolved = root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    _reject_symlink_chain(root, candidate, kind=kind)
    _require_regular_file(candidate, kind=f"Ollama {kind}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root_resolved):
        raise ValueError(f"Ollama {kind} path escaped its root")
    return resolved


def _reject_symlink_chain(root: Path, candidate: Path, *, kind: str) -> None:
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Ollama {kind} path escaped its root") from exc
    current = root
    if current.is_symlink():
        raise ValueError(f"Ollama {kind} root cannot be a symlink")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Ollama {kind} path cannot traverse symlinks")


def _manifest_blob_specs(payload: object) -> tuple[tuple[str, int], ...]:
    if not isinstance(payload, dict):
        raise ValueError("Ollama manifest must be a JSON object")
    config = payload.get("config")
    layers = payload.get("layers")
    if not isinstance(config, dict):
        raise ValueError("Ollama manifest must contain a config object")
    if not isinstance(layers, list):
        raise ValueError("Ollama manifest must contain a layers list")

    sizes: dict[str, int] = {}
    for value in (config, *layers):
        if not isinstance(value, dict):
            raise ValueError("Ollama manifest layer must be a JSON object")
        digest = value.get("digest")
        size = value.get("size")
        if not isinstance(digest, str) or not _valid_digest(digest):
            raise ValueError("Ollama manifest layer has invalid SHA-256 digest")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("Ollama manifest layer has invalid size")
        previous = sizes.get(digest)
        if previous is not None and previous != size:
            raise ValueError("Ollama manifest repeats a digest with conflicting size")
        sizes[digest] = size
    if not sizes:
        raise ValueError("Ollama manifest does not reference any blobs")
    return tuple(sorted(sizes.items()))


def _source_blob_path(models_root: Path, digest: str) -> Path:
    return _resolve_regular_member(
        models_root / "blobs",
        PurePosixPath(digest.replace(":", "-")),
        kind="blob",
    )


def _verify_blob(path: Path, *, digest: str, expected_size: int) -> None:
    _require_regular_file(path, kind="Ollama blob")
    if path.stat().st_size != expected_size:
        raise ValueError("Ollama blob size does not match manifest")
    observed = "sha256:" + _file_sha256(path)
    if observed != digest:
        raise ValueError("Ollama blob digest does not match manifest")


def _build_identity(
    *,
    models_path: Path,
    contract: OllamaArtifactContract,
    relative: PurePosixPath,
    blob_specs: tuple[tuple[str, int], ...],
) -> OllamaStagedModelStoreIdentity:
    return OllamaStagedModelStoreIdentity(
        model_id=contract.model_id,
        manifest_digest=contract.manifest_digest,
        manifest_relative_path_sha256=sha256(relative.as_posix().encode()).hexdigest(),
        staged_tree_sha256=_tree_sha256(models_path),
        referenced_blob_count=len(blob_specs),
        referenced_blob_bytes=sum(size for _, size in blob_specs),
    )


def _verify_exact_stage_members(
    models_path: Path,
    *,
    manifest_relative_path: PurePosixPath,
    blob_specs: tuple[tuple[str, int], ...],
) -> None:
    expected: set[str] = {"manifests/", "blobs/"}
    manifest_file = PurePosixPath("manifests") / manifest_relative_path
    expected.add(manifest_file.as_posix())
    parent = manifest_file.parent
    while parent.as_posix() not in {".", "manifests"}:
        expected.add(parent.as_posix() + "/")
        parent = parent.parent
    for digest, _ in blob_specs:
        expected.add("blobs/" + digest.replace(":", "-"))

    observed: set[str] = set()
    for path in models_path.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("staged Ollama store contains a symlink")
        relative = path.relative_to(models_path).as_posix()
        if path.is_dir():
            observed.add(relative + "/")
        elif path.is_file():
            observed.add(relative)
        else:
            raise RuntimeError("staged Ollama store contains an unsupported filesystem entry")
    if observed != expected:
        raise RuntimeError("staged Ollama store contains missing or unexpected filesystem entries")


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
    _require_directory(root, kind="Ollama staged models root")
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


def _require_directory(path: Path, *, kind: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{kind} must be a real directory, not a symlink")


def _require_regular_file(path: Path, *, kind: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{kind} must be a regular non-symlink file")
