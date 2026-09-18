import asyncio

import httpx
import pytest

from llm_redteam.model_roles import ModelRole, ModelsConfig, load_models_config
from llm_redteam.ollama_artifact import OllamaArtifactContract
from llm_redteam.red_artifact_identity import red_artifact_measurement_binding_sha256
from llm_redteam.red_runtime_artifact import (
    RED_RUNTIME_ARTIFACT_RECHECK_PROVENANCE_KIND,
    HttpxLocalOllamaTagsProbe,
    red_runtime_artifact_recheck_provenance,
    recheck_red_runtime_artifacts,
)
from llm_redteam.reference_artifact_qualification import (
    QualifiedArtifactBinding,
    ReferenceArtifactQualificationReport,
)

_PLANNER_DIGEST = "a" * 64
_MUTATOR_DIGEST = "b" * 64


def _models() -> ModelsConfig:
    return load_models_config("config/models.hal-smoke.example.yaml")


def _tags_payload(
    *,
    planner_digest: str = _PLANNER_DIGEST,
    mutator_digest: str = _MUTATOR_DIGEST,
    planner_size: int = 1001,
    planner_remote_host: str | None = None,
):
    planner = {
        "name": "gpt-oss:latest",
        "digest": "sha256:" + planner_digest,
        "size": planner_size,
        "details": {
            "format": "gguf",
            "family": "gptoss",
            "parameter_size": "20.9B",
            "quantization_level": "MXFP4",
        },
    }
    if planner_remote_host is not None:
        planner["remote_host"] = planner_remote_host
    return {
        "models": [
            planner,
            {
                "name": "mistral:7b-instruct",
                "digest": "sha256:" + mutator_digest,
                "size": 1002,
                "details": {
                    "format": "gguf",
                    "family": "mistral",
                    "parameter_size": "7.2B",
                    "quantization_level": "Q4_0",
                },
            },
        ]
    }


def _qualification(payload) -> ReferenceArtifactQualificationReport:
    bindings = []
    for model_id, digest in (
        ("gpt-oss:latest", _PLANNER_DIGEST),
        ("mistral:7b-instruct", _MUTATOR_DIGEST),
    ):
        contract = OllamaArtifactContract(
            model_id=model_id,
            expected_manifest_digest="sha256:" + digest,
            require_local=True,
        )
        observation = contract.verify_tags_response(payload)
        bindings.append(
            QualifiedArtifactBinding(
                model_id=model_id,
                contract_sha256=contract.contract_sha256,
                artifact_identity_sha256=observation.identity.identity_sha256,
                artifact_observation_sha256=observation.proof_sha256,
                artifact_digest=observation.identity.artifact_digest,
            )
        )
    return ReferenceArtifactQualificationReport(
        local_admission_proof_sha256="1" * 64,
        contract_set_sha256="2" * 64,
        tags_snapshot_sha256="3" * 64,
        bindings=tuple(bindings),
    )


def _expected_binding(
    models: ModelsConfig,
    qualification: ReferenceArtifactQualificationReport,
) -> str:
    planner = models.role(ModelRole.RED_PLANNER)
    mutator = models.role(ModelRole.RED_MUTATOR)
    return red_artifact_measurement_binding_sha256(
        planner_model_id=planner.model,
        planner_configuration_sha256=planner.configuration_fingerprint,
        mutator_model_id=mutator.model,
        mutator_configuration_sha256=mutator.configuration_fingerprint,
        qualification=qualification,
    )


class FakeTagsProbe:
    def __init__(self, payload) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, frozenset[str]]] = []

    async def fetch_tags(
        self,
        *,
        inference_endpoint: str,
        label: str,
        allowed_hosts: frozenset[str],
    ):
        self.calls.append((inference_endpoint, label, allowed_hosts))
        return self.payload


def test_live_red_recheck_matches_predeclared_artifacts_and_provenance() -> None:
    models = _models()
    payload = _tags_payload()
    qualification = _qualification(payload)
    expected = _expected_binding(models, qualification)
    probe = FakeTagsProbe(payload)

    report = asyncio.run(
        recheck_red_runtime_artifacts(
            models=models,
            qualification=qualification,
            expected_red_measurement_binding_sha256=expected,
            probe=probe,
        )
    )

    assert report.observed_red_measurement_binding_sha256 == expected
    assert [item.role for item in report.observations] == [
        ModelRole.RED_PLANNER,
        ModelRole.RED_MUTATOR,
    ]
    assert len(probe.calls) == 1
    assert probe.calls[0][0] == "http://127.0.0.1:11434/v1/chat/completions"
    assert len(report.proof_sha256) == 64

    provenance = red_runtime_artifact_recheck_provenance(report)
    assert provenance.kind == RED_RUNTIME_ARTIFACT_RECHECK_PROVENANCE_KIND
    assert provenance.payload == report.model_dump(mode="json")


def test_live_red_recheck_rejects_manifest_digest_drift() -> None:
    models = _models()
    qualified_payload = _tags_payload()
    qualification = _qualification(qualified_payload)
    probe = FakeTagsProbe(_tags_payload(planner_digest="c" * 64))

    with pytest.raises(ValueError, match="manifest digest"):
        asyncio.run(
            recheck_red_runtime_artifacts(
                models=models,
                qualification=qualification,
                expected_red_measurement_binding_sha256=_expected_binding(
                    models,
                    qualification,
                ),
                probe=probe,
            )
        )


def test_live_red_recheck_rejects_remote_proxy() -> None:
    models = _models()
    qualified_payload = _tags_payload()
    qualification = _qualification(qualified_payload)
    probe = FakeTagsProbe(
        _tags_payload(planner_remote_host="https://ollama.com:443")
    )

    with pytest.raises(ValueError, match="local model, not remote proxy"):
        asyncio.run(
            recheck_red_runtime_artifacts(
                models=models,
                qualification=qualification,
                expected_red_measurement_binding_sha256=_expected_binding(
                    models,
                    qualification,
                ),
                probe=probe,
            )
        )


def test_live_red_recheck_rejects_identity_metadata_drift_with_same_digest() -> None:
    models = _models()
    qualified_payload = _tags_payload()
    qualification = _qualification(qualified_payload)
    probe = FakeTagsProbe(_tags_payload(planner_size=999999))

    with pytest.raises(ValueError, match="artifact identity differs"):
        asyncio.run(
            recheck_red_runtime_artifacts(
                models=models,
                qualification=qualification,
                expected_red_measurement_binding_sha256=_expected_binding(
                    models,
                    qualification,
                ),
                probe=probe,
            )
        )


def test_live_red_recheck_rejects_predeclared_binding_mismatch_before_probe() -> None:
    models = _models()
    payload = _tags_payload()
    qualification = _qualification(payload)
    probe = FakeTagsProbe(payload)

    with pytest.raises(ValueError, match="predeclared measurement binding"):
        asyncio.run(
            recheck_red_runtime_artifacts(
                models=models,
                qualification=qualification,
                expected_red_measurement_binding_sha256="0" * 64,
                probe=probe,
            )
        )

    assert probe.calls == []


def test_live_red_recheck_rejects_nonlocal_endpoint_before_probe() -> None:
    raw = _models().model_dump(mode="json", by_alias=True)
    raw["roles"]["red_planner"]["endpoint"] = (
        "https://example.com/v1/chat/completions"
    )
    models = ModelsConfig.model_validate(raw)
    payload = _tags_payload()
    qualification = _qualification(payload)
    probe = FakeTagsProbe(payload)

    with pytest.raises(ValueError, match="not loopback or explicitly allowed"):
        asyncio.run(
            recheck_red_runtime_artifacts(
                models=models,
                qualification=qualification,
                expected_red_measurement_binding_sha256=_expected_binding(
                    models,
                    qualification,
                ),
                probe=probe,
            )
        )

    assert probe.calls == []


def test_httpx_probe_calls_only_local_ollama_tags_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=_tags_payload())

    async def run_probe():
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        probe = HttpxLocalOllamaTagsProbe(client=client)
        try:
            return await probe.fetch_tags(
                inference_endpoint="http://127.0.0.1:11434/v1/chat/completions",
                label="red_planner",
                allowed_hosts=frozenset(),
            )
        finally:
            await client.aclose()

    payload = asyncio.run(run_probe())

    assert payload == _tags_payload()
    assert len(requests) == 1
    assert str(requests[0].url) == "http://127.0.0.1:11434/api/tags"
    assert requests[0].method == "GET"
