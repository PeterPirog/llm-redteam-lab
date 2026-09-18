import json
from pathlib import Path

from typer.testing import CliRunner

from llm_redteam.cli import app

runner = CliRunner()

_PLANNER = "gpt-oss:latest"
_MUTATOR = "mistral:7b-instruct"
_BLUE = "ornith-1.5:9b"
_DIGESTS = {
    _PLANNER: "b" * 64,
    _MUTATOR: "c" * 64,
    _BLUE: "a" * 64,
}
_SIZES = {
    _PLANNER: 1001,
    _MUTATOR: 1002,
    _BLUE: 1003,
}


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _runtime_documents(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    inventory_records = []
    tags_records = []
    capabilities = {
        _PLANNER: ["completion", "thinking"],
        _MUTATOR: ["completion"],
        _BLUE: ["completion", "vision"],
    }
    for model_id in (_PLANNER, _MUTATOR, _BLUE):
        inventory_records.append(
            {
                "id": model_id,
                "owned_by": "ollama",
                "ollama": {
                    "digest": _DIGESTS[model_id],
                    "size": _SIZES[model_id],
                    "details": {
                        "family": "synthetic",
                        "parameter_size": "test",
                        "quantization_level": "Q4",
                    },
                    "capabilities": capabilities[model_id],
                },
            }
        )
        tags_records.append(
            {
                "name": model_id,
                "digest": "sha256:" + _DIGESTS[model_id],
                "size": _SIZES[model_id],
                "details": {
                    "family": "synthetic",
                    "parameter_size": "test",
                    "quantization_level": "Q4",
                },
            }
        )

    inventory = _write_json(tmp_path / "models.json", {"data": inventory_records})
    tags = _write_json(tmp_path / "tags.json", {"models": tags_records})
    contracts = _write_json(
        tmp_path / "contracts.json",
        {
            "version": 1,
            "contracts": [
                {
                    "model_id": model_id,
                    "expected_manifest_digest": "sha256:" + _DIGESTS[model_id],
                    "require_local": True,
                }
                for model_id in (_PLANNER, _MUTATOR, _BLUE)
            ],
        },
    )
    pins = _write_json(
        tmp_path / "pins.json",
        {
            "version": 1,
            "staged_blue_store_identity": {
                "model_id": _BLUE,
                "manifest_digest": "sha256:" + _DIGESTS[_BLUE],
                "manifest_relative_path_sha256": "1" * 64,
                "staged_tree_sha256": "2" * 64,
                "referenced_blob_count": 3,
                "referenced_blob_bytes": 4096,
            },
            "opencode_application_version": "1.2.3-test",
            "opencode_image_ref": "synthetic/opencode@sha256:" + "3" * 64,
            "opencode_image_id": "sha256:" + "4" * 64,
            "ollama_peer_image_ref": "synthetic/ollama-probe@sha256:" + "5" * 64,
            "ollama_peer_image_id": "sha256:" + "6" * 64,
        },
    )
    return inventory, contracts, tags, pins


def test_hal_smoke_preflight_static_mode_requires_no_hal_evidence() -> None:
    result = runner.invoke(
        app,
        [
            "hal-smoke-preflight",
            "--models",
            "config/models.hal-smoke.example.yaml",
            "--blue-model",
            _BLUE,
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["phase"] == "static"
    assert payload["live_runtime_admitted"] is False
    assert payload["static_plan"]["red_planner_model_id"] == _PLANNER
    assert payload["static_plan"]["red_mutator_model_id"] == _MUTATOR
    assert payload["static_plan"]["blue_model_id"] == _BLUE
    assert len(payload["required_offline_inputs"]) == 4


def test_hal_smoke_preflight_rejects_partial_runtime_evidence(tmp_path: Path) -> None:
    inventory, _, _, _ = _runtime_documents(tmp_path)

    result = runner.invoke(
        app,
        [
            "hal-smoke-preflight",
            "--model-inventory",
            str(inventory),
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert "requires all of" in result.stdout


def test_hal_smoke_preflight_composes_saved_hal_evidence_without_runtime_calls(
    tmp_path: Path,
) -> None:
    inventory, contracts, tags, pins = _runtime_documents(tmp_path)

    result = runner.invoke(
        app,
        [
            "hal-smoke-preflight",
            "--models",
            "config/models.hal-smoke.example.yaml",
            "--blue-model",
            _BLUE,
            "--model-inventory",
            str(inventory),
            "--artifact-contracts",
            str(contracts),
            "--ollama-tags-snapshot",
            str(tags),
            "--runtime-pins",
            str(pins),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["phase"] == "offline_composed"
    assert payload["live_runtime_admitted"] is False
    assert payload["blue_artifact_digest"] == "sha256:" + _DIGESTS[_BLUE]
    assert len(payload["composition_sha256"]) == 64
    assert len(payload["model_network_profile_sha256"]) == 64
    assert len(payload["model_peer_profile_sha256"]) == 64
    assert "opencode_environment_attestation" in payload["live_evidence_requirements"]
