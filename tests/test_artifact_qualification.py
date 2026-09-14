import json
from pathlib import Path

import pytest

from llm_redteam.artifact_qualification import (
    OllamaArtifactContractSet,
    load_ollama_artifact_contracts,
    load_ollama_tags_snapshot,
    qualify_admitted_ollama_artifacts,
)
from llm_redteam.model_inventory import (
    LocalModelAdmissionBinding,
    LocalOnlyAdmissionReport,
    OpenWebUIOllamaInventory,
)

_DIGESTS = {
    "planner-local": "a" * 64,
    "mutator-local": "b" * 64,
    "blue-local": "c" * 64,
}
_SIZES = {
    "planner-local": 100,
    "mutator-local": 200,
    "blue-local": 300,
}


def _openwebui_payload() -> dict[str, object]:
    return {
        "data": [
            {
                "id": model_id,
                "owned_by": "ollama",
                "ollama": {
                    "digest": digest,
                    "size": _SIZES[model_id],
                    "details": {
                        "family": "synthetic",
                        "parameter_size": "9B",
                        "quantization_level": "Q4_K_M",
                    },
                    "capabilities": ["completion", "thinking"],
                    "connection_type": "local",
                },
            }
            for model_id, digest in _DIGESTS.items()
        ]
    }


def _inventory() -> OpenWebUIOllamaInventory:
    return OpenWebUIOllamaInventory.from_openwebui_response(_openwebui_payload())


def _admission(inventory: OpenWebUIOllamaInventory) -> LocalOnlyAdmissionReport:
    labels = {
        "planner-local": "red_planner",
        "mutator-local": "red_mutator",
        "blue-local": "blue",
    }
    return LocalOnlyAdmissionReport(
        inventory_sha256=inventory.inventory_sha256,
        bindings=tuple(
            LocalModelAdmissionBinding(
                label=labels[record.model_id],
                model_id=record.model_id,
                inventory_record_sha256=record.record_sha256,
                endpoint_sha256="e" * 64,
            )
            for record in inventory.records
        ),
        blue_model_id="blue-local",
    )


def _contracts(**digest_updates: str) -> OllamaArtifactContractSet:
    return OllamaArtifactContractSet.model_validate(
        {
            "version": 1,
            "models": [
                {
                    "model_id": model_id,
                    "manifest_digest": digest_updates.get(model_id, digest),
                }
                for model_id, digest in _DIGESTS.items()
            ],
        }
    )


def _tags(**digest_updates: str) -> dict[str, object]:
    return {
        "models": [
            {
                "name": model_id,
                "model": model_id,
                "digest": digest_updates.get(model_id, digest),
                "size": _SIZES[model_id],
                "details": {
                    "format": "gguf",
                    "family": "synthetic",
                    "parameter_size": "9B",
                    "quantization_level": "Q4_K_M",
                },
            }
            for model_id, digest in _DIGESTS.items()
        ]
    }


def test_qualification_binds_every_admitted_model_to_exact_artifact() -> None:
    inventory = _inventory()
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
    assert report.admission_proof_sha256 == admission.proof_sha256
    assert report.inventory_sha256 == inventory.inventory_sha256
    assert len(report.tags_snapshot_sha256) == 64
    assert len(report.proof_sha256) == 64
    by_model = {binding.model_id: binding for binding in report.bindings}
    assert by_model["blue-local"].labels == ("blue",)
    assert by_model["blue-local"].artifact_digest == "sha256:" + "c" * 64
    assert all(len(binding.artifact_identity_sha256) == 64 for binding in report.bindings)
    assert all(len(binding.artifact_contract_sha256) == 64 for binding in report.bindings)


def test_qualification_rejects_different_inventory_than_admission_snapshot() -> None:
    inventory = _inventory()
    admission = _admission(inventory).model_copy(update={"inventory_sha256": "f" * 64})

    with pytest.raises(ValueError, match="inventory does not match admission proof"):
        qualify_admitted_ollama_artifacts(
            admission=admission,
            inventory=inventory,
            contracts=_contracts(),
            tags_snapshot=_tags(),
        )


def test_qualification_requires_contract_for_every_admitted_model() -> None:
    inventory = _inventory()
    contracts = OllamaArtifactContractSet.model_validate(
        {
            "version": 1,
            "models": [
                {"model_id": "blue-local", "manifest_digest": _DIGESTS["blue-local"]},
                {
                    "model_id": "planner-local",
                    "manifest_digest": _DIGESTS["planner-local"],
                },
            ],
        }
    )

    with pytest.raises(ValueError, match="exactly one model: mutator-local"):
        qualify_admitted_ollama_artifacts(
            admission=_admission(inventory),
            inventory=inventory,
            contracts=contracts,
            tags_snapshot=_tags(),
        )


def test_qualification_rejects_wrong_predeclared_digest() -> None:
    inventory = _inventory()

    with pytest.raises(ValueError, match="manifest digest"):
        qualify_admitted_ollama_artifacts(
            admission=_admission(inventory),
            inventory=inventory,
            contracts=_contracts(**{"blue-local": "f" * 64}),
            tags_snapshot=_tags(),
        )


def test_qualification_rejects_tags_inventory_disagreement_even_if_contract_matches_tags() -> None:
    inventory = _inventory()
    changed_digest = "f" * 64

    with pytest.raises(ValueError, match="tags digest disagrees"):
        qualify_admitted_ollama_artifacts(
            admission=_admission(inventory),
            inventory=inventory,
            contracts=_contracts(**{"blue-local": changed_digest}),
            tags_snapshot=_tags(**{"blue-local": changed_digest}),
        )


def test_qualification_rejects_stale_admission_record_binding() -> None:
    inventory = _inventory()
    admission = _admission(inventory)
    first = admission.bindings[0]
    stale = LocalOnlyAdmissionReport(
        inventory_sha256=admission.inventory_sha256,
        bindings=(
            first.model_copy(update={"inventory_record_sha256": "f" * 64}),
            *admission.bindings[1:],
        ),
        blue_model_id=admission.blue_model_id,
    )

    with pytest.raises(ValueError, match="inventory binding mismatch"):
        qualify_admitted_ollama_artifacts(
            admission=stale,
            inventory=inventory,
            contracts=_contracts(),
            tags_snapshot=_tags(),
        )


def test_loaders_accept_yaml_contracts_and_fenced_tags(tmp_path: Path) -> None:
    contracts_path = tmp_path / "contracts.yaml"
    tags_path = tmp_path / "tags.md"
    contracts_path.write_text(
        "version: 1\nmodels:\n"
        "  - model_id: blue-local\n"
        f"    manifest_digest: {'c' * 64}\n",
        encoding="utf-8",
    )
    tags_path.write_text(
        "```json\n" + json.dumps({"models": []}) + "\n```\n",
        encoding="utf-8",
    )

    contracts = load_ollama_artifact_contracts(contracts_path)
    tags = load_ollama_tags_snapshot(tags_path)

    assert contracts.require("blue-local").manifest_digest == "sha256:" + "c" * 64
    assert tags == {"models": []}
