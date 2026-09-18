from copy import deepcopy

import pytest

from llm_redteam.hal_smoke_preflight import (
    HalSmokeRuntimePins,
    build_hal_smoke_static_plan,
    compose_hal_smoke_offline,
)
from llm_redteam.model_inventory import (
    LocalModelAdmissionBinding,
    LocalOnlyAdmissionReport,
)
from llm_redteam.model_roles import ModelsConfig, load_models_config
from llm_redteam.ollama_model_staging import OllamaStagedModelStoreIdentity
from llm_redteam.reference_artifact_qualification import (
    QualifiedArtifactBinding,
    ReferenceArtifactQualificationReport,
)
from llm_redteam.target_trial_isolation import TargetIsolationLevel

_BLUE = "ornith-1.5:9b"
_BLUE_DIGEST = "a" * 64


def _models() -> ModelsConfig:
    return load_models_config("config/models.hal-smoke.example.yaml")


def _admission(plan):
    bindings = (
        LocalModelAdmissionBinding(
            label="red_planner",
            model_id=plan.red_planner_model_id,
            inventory_record_sha256="1" * 64,
            endpoint_sha256=plan.red_planner_endpoint_sha256,
        ),
        LocalModelAdmissionBinding(
            label="red_mutator",
            model_id=plan.red_mutator_model_id,
            inventory_record_sha256="2" * 64,
            endpoint_sha256=plan.red_mutator_endpoint_sha256,
        ),
        LocalModelAdmissionBinding(
            label="blue",
            model_id=plan.blue_model_id,
            inventory_record_sha256="3" * 64,
            endpoint_sha256="4" * 64,
        ),
    )
    return LocalOnlyAdmissionReport(
        inventory_sha256="5" * 64,
        bindings=bindings,
        blue_model_id=plan.blue_model_id,
    )


def _qualification(plan, admission):
    digests = {
        plan.red_planner_model_id: "b" * 64,
        plan.red_mutator_model_id: "c" * 64,
        plan.blue_model_id: _BLUE_DIGEST,
    }
    return ReferenceArtifactQualificationReport(
        local_admission_proof_sha256=admission.proof_sha256,
        contract_set_sha256="6" * 64,
        tags_snapshot_sha256="7" * 64,
        bindings=tuple(
            QualifiedArtifactBinding(
                model_id=model_id,
                contract_sha256="8" * 64,
                artifact_identity_sha256="9" * 64,
                artifact_observation_sha256="d" * 64,
                artifact_digest="sha256:" + digest,
            )
            for model_id, digest in sorted(digests.items())
        ),
    )


def _pins(*, model_id: str = _BLUE, manifest_digest: str | None = None):
    return HalSmokeRuntimePins(
        staged_blue_store_identity=OllamaStagedModelStoreIdentity(
            model_id=model_id,
            manifest_digest=manifest_digest or "sha256:" + _BLUE_DIGEST,
            manifest_relative_path_sha256="e" * 64,
            staged_tree_sha256="f" * 64,
            referenced_blob_count=3,
            referenced_blob_bytes=4096,
        ),
        opencode_application_version="1.2.3-test",
        opencode_image_ref="synthetic/opencode@sha256:" + "1" * 64,
        opencode_image_id="sha256:" + "2" * 64,
        ollama_peer_image_ref="synthetic/ollama-probe@sha256:" + "3" * 64,
        ollama_peer_image_id="sha256:" + "4" * 64,
    )


def test_static_plan_uses_bounded_local_only_smoke_profile() -> None:
    plan = build_hal_smoke_static_plan(models=_models(), blue_model_id=_BLUE)

    assert plan.red_planner_model_id == "gpt-oss:latest"
    assert plan.red_mutator_model_id == "mistral:7b-instruct"
    assert plan.blue_model_id == _BLUE
    assert plan.cloud_fallback_allowed is False
    assert plan.exact_local_artifact_required is True
    assert plan.required_isolation == TargetIsolationLevel.DISPOSABLE_SANDBOX
    assert len(plan.plan_sha256) == 64


def test_static_plan_rejects_cloud_fallback_and_extra_enabled_roles() -> None:
    raw = _models().model_dump(mode="python", by_alias=True)
    cloud = deepcopy(raw)
    cloud["policy"]["allow_cloud_fallback"] = True
    with pytest.raises(ValueError, match="forbids cloud fallback"):
        build_hal_smoke_static_plan(
            models=ModelsConfig.model_validate(cloud),
            blue_model_id=_BLUE,
        )

    extra = deepcopy(raw)
    extra["roles"]["judge_semantic"]["enabled"] = True
    with pytest.raises(ValueError, match="exactly red_planner and red_mutator"):
        build_hal_smoke_static_plan(
            models=ModelsConfig.model_validate(extra),
            blue_model_id=_BLUE,
        )


def test_offline_composition_binds_exact_blue_artifact_and_runtime_policy() -> None:
    static = build_hal_smoke_static_plan(models=_models(), blue_model_id=_BLUE)
    admission = _admission(static)
    qualification = _qualification(static, admission)
    pins = _pins()

    composition = compose_hal_smoke_offline(
        static_plan=static,
        admission=admission,
        qualification=qualification,
        pins=pins,
    )

    assert composition.blue_artifact_digest == "sha256:" + _BLUE_DIGEST
    assert composition.model_peer.model_id == _BLUE
    assert composition.model_peer.gpu_access is True
    assert composition.model_peer.command == ("ollama", "serve")
    assert composition.model_network.model_endpoint_origin == "http://model-peer:11434"
    assert composition.opencode_launch_policy.model_binding.model_id == _BLUE
    assert composition.opencode_launch_policy.model_binding.base_url == (
        "http://model-peer:11434/v1"
    )
    assert composition.opencode_agent.required_secret_env_names == (
        "OPENCODE_SERVER_PASSWORD",
    )
    assert composition.sandbox_policy.disposable_workspace is True
    assert composition.sandbox_policy.external_network_denied is True
    assert composition.target_config.application_version == "1.2.3-test"
    assert composition.live_runtime_admitted is False
    assert "runtime_blue_artifact_probe_binding" in composition.live_evidence_requirements
    assert "per_trial_cleanup_proof" in composition.live_evidence_requirements
    assert len(composition.composition_sha256) == 64


def test_offline_composition_rejects_admission_drift() -> None:
    static = build_hal_smoke_static_plan(models=_models(), blue_model_id=_BLUE)
    admission = _admission(static)
    qualification = _qualification(static, admission)
    drifted = admission.model_copy(
        update={
            "bindings": tuple(
                binding.model_copy(update={"model_id": "other"})
                if binding.label == "red_mutator"
                else binding
                for binding in admission.bindings
            )
        }
    )

    with pytest.raises(ValueError, match="do not exactly match"):
        compose_hal_smoke_offline(
            static_plan=static,
            admission=drifted,
            qualification=qualification,
            pins=_pins(),
        )


def test_offline_composition_rejects_staged_blue_manifest_drift() -> None:
    static = build_hal_smoke_static_plan(models=_models(), blue_model_id=_BLUE)
    admission = _admission(static)
    qualification = _qualification(static, admission)

    with pytest.raises(ValueError, match="manifest disagrees"):
        compose_hal_smoke_offline(
            static_plan=static,
            admission=admission,
            qualification=qualification,
            pins=_pins(manifest_digest="sha256:" + "0" * 64),
        )


def test_offline_composition_rejects_staged_blue_model_drift() -> None:
    static = build_hal_smoke_static_plan(models=_models(), blue_model_id=_BLUE)
    admission = _admission(static)
    qualification = _qualification(static, admission)

    with pytest.raises(ValueError, match="store model differs"):
        compose_hal_smoke_offline(
            static_plan=static,
            admission=admission,
            qualification=qualification,
            pins=_pins(model_id="other-local-model"),
        )
