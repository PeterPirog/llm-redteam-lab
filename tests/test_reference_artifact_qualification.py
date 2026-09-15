import json

import pytest

from llm_redteam.model_inventory import (
    OpenWebUIOllamaInventory,
    validate_local_only_model_selection,
)
from llm_redteam.model_roles import ModelsConfig
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.reference_artifact_qualification import (
    OllamaArtifactContractSet,
    qualify_admitted_ollama_artifacts,
)


def _inventory_payload(*, blue_digest: str = "c") -> dict[str, object]:
    def record(model_id: str, digest: str, size: int, capabilities: list[str]):
        return {
            "id": model_id,
            "owned_by": "ollama",
            "ollama": {
                "digest": digest * 64,
                "size": size,
                "details": {"family": model_id.split("-")[0]},
                "capabilities": capabilities,
                "connection_type": "local",
            },
        }

    return {
        "data": [
            record("planner-local", "a", 100, ["completion", "thinking"]),
            record("mutator-local", "b", 200, ["completion"]),
            record("blue-local", blue_digest, 300, ["completion"]),
        ]
    }


def _models() -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner-local",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator-local",
                    "class": "local",
                    "capabilities": ["text"],
                    "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
                },
            },
        }
    )


def _admission(inventory: OpenWebUIOllamaInventory):
    return validate_local_only_model_selection(
        models=_models(),
        inventory=inventory,
        blue_model_id="blue-local",
        blue_endpoint="http://127.0.0.1:11434",
    )


def _contracts(*, blue_digest: str = "c") -> OllamaArtifactContractSet:
    return OllamaArtifactContractSet(
        contracts=(
            OllamaArtifactContract(
                model_id="planner-local", expected_manifest_digest="a" * 64
            ),
            OllamaArtifactContract(
                model_id="mutator-local", expected_manifest_digest="b" * 64
            ),
            OllamaArtifactContract(
                model_id="blue-local", expected_manifest_digest=blue_digest * 64
            ),
        )
    )


def _tags(*, blue_digest: str = "c", blue_size: int = 300) -> dict[str, object]:
    return {
        "models": [
            {
                "name": "planner-local",
                "digest": "a" * 64,
                "size": 100,
                "details": {"family": "planner"},
            },
            {
                "name": "mutator-local",
                "digest": "b" * 64,
                "size": 200,
                "details": {"family": "mutator"},
            },
            {
                "name": "blue-local",
                "digest": blue_digest * 64,
                "size": blue_size,
                "details": {"family": "blue"},
            },
        ]
    }


def test_qualification_binds_every_admitted_model_to_exact_artifact() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_inventory_payload())
    admission = _admission(inventory)

    report = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=_contracts(),
        tags_snapshot=_tags(),
    )

    assert report.qualified_model_ids == (
        "blue-local",
        "mutator-local",
        "planner-local",
    )
    assert report.local_admission_proof_sha256 == admission.proof_sha256
    assert len(report.proof_sha256) == 64
    assert all(binding.artifact_digest.startswith("sha256:") for binding in report.bindings)


def test_contract_set_must_exactly_cover_admitted_models() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_inventory_payload())
    admission = _admission(inventory)
    incomplete = OllamaArtifactContractSet(
        contracts=(
            OllamaArtifactContract(
                model_id="planner-local", expected_manifest_digest="a" * 64
            ),
            OllamaArtifactContract(
                model_id="blue-local", expected_manifest_digest="c" * 64
            ),
        )
    )

    with pytest.raises(ValueError, match="exactly cover"):
        qualify_admitted_ollama_artifacts(
            admission=admission,
            inventory=inventory,
            contracts=incomplete,
            tags_snapshot=_tags(),
        )


def test_duplicate_contract_model_is_rejected() -> None:
    contract = OllamaArtifactContract(
        model_id="planner-local", expected_manifest_digest="a" * 64
    )

    with pytest.raises(ValueError, match="unique"):
        OllamaArtifactContractSet(contracts=(contract, contract))


def test_predeclared_digest_mismatch_is_rejected() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_inventory_payload())

    with pytest.raises(ValueError, match="manifest digest"):
        qualify_admitted_ollama_artifacts(
            admission=_admission(inventory),
            inventory=inventory,
            contracts=_contracts(),
            tags_snapshot=_tags(blue_digest="d"),
        )


def test_inventory_and_tags_digest_disagreement_is_rejected() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(
        _inventory_payload(blue_digest="c")
    )

    with pytest.raises(ValueError, match="disagrees between admission inventory"):
        qualify_admitted_ollama_artifacts(
            admission=_admission(inventory),
            inventory=inventory,
            contracts=_contracts(blue_digest="d"),
            tags_snapshot=_tags(blue_digest="d"),
        )


def test_inventory_and_tags_size_disagreement_is_rejected() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_inventory_payload())

    with pytest.raises(ValueError, match="artifact size disagrees"):
        qualify_admitted_ollama_artifacts(
            admission=_admission(inventory),
            inventory=inventory,
            contracts=_contracts(),
            tags_snapshot=_tags(blue_size=301),
        )


def test_report_hash_is_independent_of_contract_declaration_order() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_inventory_payload())
    admission = _admission(inventory)
    contracts = _contracts()
    reversed_contracts = OllamaArtifactContractSet(contracts=tuple(reversed(contracts.contracts)))

    left = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=contracts,
        tags_snapshot=_tags(),
    )
    right = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=reversed_contracts,
        tags_snapshot=_tags(),
    )

    assert left.proof_sha256 == right.proof_sha256


def test_tags_snapshot_hash_tracks_exact_saved_response() -> None:
    inventory = OpenWebUIOllamaInventory.from_openwebui_response(_inventory_payload())
    admission = _admission(inventory)
    tags = _tags()
    first = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=_contracts(),
        tags_snapshot=tags,
    )
    changed = json.loads(json.dumps(tags))
    changed["server_note"] = "different snapshot"
    second = qualify_admitted_ollama_artifacts(
        admission=admission,
        inventory=inventory,
        contracts=_contracts(),
        tags_snapshot=changed,
    )

    assert first.tags_snapshot_sha256 != second.tags_snapshot_sha256
    assert first.proof_sha256 != second.proof_sha256
