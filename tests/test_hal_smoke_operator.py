import json
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.hal_smoke_operator import (
    capture_hal_smoke_runtime,
    verify_hal_smoke_runtime_images,
)
from llm_redteam.ollama_artifact import OllamaArtifactContract

_MODEL_ID = "synthetic-blue"
_MANIFEST_RELATIVE = "registry.ollama.ai/library/synthetic-blue/latest"
_OPENCODE_REF = "example/opencode@sha256:" + "1" * 64
_OLLAMA_REF = "example/ollama-probe@sha256:" + "2" * 64
_OPENCODE_ID = "sha256:" + "3" * 64
_OLLAMA_ID = "sha256:" + "4" * 64


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _source_store(tmp_path: Path) -> tuple[Path, bytes]:
    models = tmp_path / "source-models"
    manifests = (
        models
        / "manifests"
        / "registry.ollama.ai"
        / "library"
        / "synthetic-blue"
    )
    blobs = models / "blobs"
    manifests.mkdir(parents=True)
    blobs.mkdir(parents=True)

    config = b'{"model_format":"gguf"}\n'
    weights = b"synthetic-blue-weights"
    config_digest = "sha256:" + _sha(config)
    weights_digest = "sha256:" + _sha(weights)
    manifest = {
        "schemaVersion": 2,
        "config": {"digest": config_digest, "size": len(config)},
        "layers": [{"digest": weights_digest, "size": len(weights)}],
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode() + b"\n"
    (manifests / "latest").write_bytes(manifest_bytes)
    (blobs / config_digest.replace(":", "-")).write_bytes(config)
    (blobs / weights_digest.replace(":", "-")).write_bytes(weights)
    return models, manifest_bytes


class FakeDockerRunner:
    def __init__(
        self,
        *,
        opencode_id: str = _OPENCODE_ID,
        ollama_id: str = _OLLAMA_ID,
    ) -> None:
        self.openc_id = opencode_id
        self.ollama_id = ollama_id
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds == 30.0
        self.calls.append(argv)
        if argv[-1] == _OPENCODE_REF:
            return CommandResult(returncode=0, stdout=self.openc_id + "\n")
        if argv[-1] == _OLLAMA_REF:
            return CommandResult(returncode=0, stdout=self.ollama_id + "\n")
        return CommandResult(returncode=1, stderr="not found")


def test_capture_hal_runtime_stages_exact_blue_and_pins_local_images(
    tmp_path: Path,
) -> None:
    source, manifest_bytes = _source_store(tmp_path)
    contract = OllamaArtifactContract(
        model_id=_MODEL_ID,
        expected_manifest_digest="sha256:" + _sha(manifest_bytes),
        require_local=True,
    )
    runner = FakeDockerRunner()

    captured = capture_hal_smoke_runtime(
        blue_artifact_contract=contract,
        manifest_relative_path=_MANIFEST_RELATIVE,
        source_models_root=source,
        staging_root=tmp_path / "staging",
        opencode_application_version="1.2.3",
        opencode_image_ref=_OPENCODE_REF,
        ollama_peer_image_ref=_OLLAMA_REF,
        docker_runner=runner,
    )

    assert captured.runtime_pins.staged_blue_store_identity == captured.staged_store.identity
    assert captured.runtime_pins.opencode_image_id == _OPENCODE_ID
    assert captured.runtime_pins.ollama_peer_image_id == _OLLAMA_ID
    assert captured.runtime_pins.opencode_application_version == "1.2.3"
    assert len(runner.calls) == 2
    expected_prefix = ("docker", "image", "inspect", "--format", "{{.Id}}")
    assert all(call[:5] == expected_prefix for call in runner.calls)


def test_capture_hal_runtime_rejects_unpinned_image_ref_before_inspect(
    tmp_path: Path,
) -> None:
    source, manifest_bytes = _source_store(tmp_path)
    contract = OllamaArtifactContract(
        model_id=_MODEL_ID,
        expected_manifest_digest="sha256:" + _sha(manifest_bytes),
        require_local=True,
    )
    runner = FakeDockerRunner()

    with pytest.raises(ValueError, match="digest-pinned"):
        capture_hal_smoke_runtime(
            blue_artifact_contract=contract,
            manifest_relative_path=_MANIFEST_RELATIVE,
            source_models_root=source,
            staging_root=tmp_path / "staging",
            opencode_application_version="1.2.3",
            opencode_image_ref="example/opencode:latest",
            ollama_peer_image_ref=_OLLAMA_REF,
            docker_runner=runner,
        )


def test_verify_hal_runtime_images_rejects_local_image_id_drift(tmp_path: Path) -> None:
    source, manifest_bytes = _source_store(tmp_path)
    contract = OllamaArtifactContract(
        model_id=_MODEL_ID,
        expected_manifest_digest="sha256:" + _sha(manifest_bytes),
        require_local=True,
    )
    captured = capture_hal_smoke_runtime(
        blue_artifact_contract=contract,
        manifest_relative_path=_MANIFEST_RELATIVE,
        source_models_root=source,
        staging_root=tmp_path / "staging",
        opencode_application_version="1.2.3",
        opencode_image_ref=_OPENCODE_REF,
        ollama_peer_image_ref=_OLLAMA_REF,
        docker_runner=FakeDockerRunner(),
    )

    with pytest.raises(ValueError, match="OpenCode image ID differs"):
        verify_hal_smoke_runtime_images(
            runtime_pins=captured.runtime_pins,
            docker_runner=FakeDockerRunner(opencode_id="sha256:" + "f" * 64),
        )
