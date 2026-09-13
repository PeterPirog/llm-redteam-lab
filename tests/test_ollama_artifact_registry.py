from pathlib import Path

import pytest

from llm_redteam.ollama_artifact_registry import (
    OllamaArtifactRegistry,
    load_ollama_artifact_registry,
)


def _registry() -> OllamaArtifactRegistry:
    return OllamaArtifactRegistry.model_validate(
        {
            "version": 1,
            "provider": "ollama",
            "source": "synthetic-inventory",
            "require_local": True,
            "artifacts": {
                "planner:latest": {
                    "digest": "sha256:" + "a" * 64,
                    "roles": ["red_planner"],
                },
                "judge:latest": {
                    "digest": "sha256:" + "b" * 64,
                    "roles": ["judge_semantic"],
                },
            },
        }
    )


def _record(model: str, digest_char: str, *, remote_host: str | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        "name": model,
        "model": model,
        "digest": "sha256:" + digest_char * 64,
        "size": 1024,
        "details": {
            "format": "gguf",
            "family": "synthetic",
            "parameter_size": "9B",
            "quantization_level": "Q4_K_M",
        },
    }
    if remote_host is not None:
        record["remote_host"] = remote_host
    return record


def _payload(*, planner_digest: str = "a", remote_planner: bool = False) -> dict[str, object]:
    return {
        "models": [
            _record(
                "planner:latest",
                planner_digest,
                remote_host="https://ollama.com" if remote_planner else None,
            ),
            _record("judge:latest", "b"),
            _record("unrelated:latest", "c"),
        ]
    }


def test_registry_verifies_only_requested_models_and_returns_provider_neutral_map() -> None:
    registry = _registry()
    qualification = registry.verify_tags_response(
        _payload(),
        required_model_ids=("judge:latest", "planner:latest"),
    )

    assert len(qualification.observations) == 2
    assert len(qualification.qualification_sha256) == 64
    assert qualification.registry_sha256 == registry.registry_sha256
    assert set(qualification.artifact_map) == {
        ("ollama", "planner:latest"),
        ("ollama", "judge:latest"),
    }
    assert qualification.artifact_map[("ollama", "planner:latest")].local_artifact is True


def test_registry_rejects_remote_proxy_even_when_digest_matches() -> None:
    with pytest.raises(ValueError, match="local model, not remote proxy"):
        _registry().verify_tags_response(
            _payload(remote_planner=True),
            required_model_ids=("planner:latest",),
        )


def test_registry_rejects_changed_manifest_under_same_model_tag() -> None:
    with pytest.raises(ValueError, match="manifest digest"):
        _registry().verify_tags_response(
            _payload(planner_digest="d"),
            required_model_ids=("planner:latest",),
        )


def test_registry_rejects_undeclared_empty_or_duplicate_requirements() -> None:
    registry = _registry()
    with pytest.raises(ValueError, match="not declared"):
        registry.verify_tags_response(
            _payload(),
            required_model_ids=("missing:latest",),
        )
    with pytest.raises(ValueError, match="at least one"):
        registry.verify_tags_response(_payload(), required_model_ids=())
    with pytest.raises(ValueError, match="must be unique"):
        registry.verify_tags_response(
            _payload(),
            required_model_ids=("planner:latest", "planner:latest"),
        )


def test_registry_hash_is_independent_of_artifact_mapping_order() -> None:
    first = _registry()
    second = OllamaArtifactRegistry.model_validate(
        {
            "version": 1,
            "provider": "ollama",
            "source": "synthetic-inventory",
            "require_local": True,
            "artifacts": {
                "judge:latest": {
                    "digest": "sha256:" + "b" * 64,
                    "roles": ["judge_semantic"],
                },
                "planner:latest": {
                    "digest": "sha256:" + "a" * 64,
                    "roles": ["red_planner"],
                },
            },
        }
    )

    assert first.registry_sha256 == second.registry_sha256


def test_registry_role_hints_are_hash_normalized_but_not_used_as_authorization() -> None:
    first = OllamaArtifactRegistry.model_validate(
        {
            "version": 1,
            "provider": "ollama",
            "source": "synthetic-inventory",
            "artifacts": {
                "planner:latest": {
                    "digest": "sha256:" + "a" * 64,
                    "roles": ["red_planner", "optional_blue"],
                }
            },
        }
    )
    second = OllamaArtifactRegistry.model_validate(
        {
            "version": 1,
            "provider": "ollama",
            "source": "synthetic-inventory",
            "artifacts": {
                "planner:latest": {
                    "digest": "sha256:" + "a" * 64,
                    "roles": ["optional_blue", "red_planner"],
                }
            },
        }
    )

    assert first.registry_sha256 == second.registry_sha256
    qualification = first.verify_tags_response(
        _payload(),
        required_model_ids=("planner:latest",),
    )
    assert qualification.artifact_map[("ollama", "planner:latest")].model_id == "planner:latest"


def test_registry_loader_reads_versioned_yaml(tmp_path: Path) -> None:
    path = tmp_path / "artifacts.yaml"
    path.write_text(
        "\n".join(
            [
                "version: 1",
                "provider: ollama",
                "source: synthetic-file",
                "require_local: true",
                "artifacts:",
                "  planner:latest:",
                f"    digest: sha256:{'a' * 64}",
                "    roles: [red_planner]",
            ]
        ),
        encoding="utf-8",
    )

    loaded = load_ollama_artifact_registry(path)

    assert loaded.source == "synthetic-file"
    assert loaded.contract_for("planner:latest").manifest_digest == "sha256:" + "a" * 64


def test_registry_loader_rejects_invalid_or_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        load_ollama_artifact_registry(tmp_path / "missing.yaml")

    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("version: 1\nprovider: ollama\nartifacts: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid Ollama artifact registry"):
        load_ollama_artifact_registry(invalid)
