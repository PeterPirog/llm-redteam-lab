import pytest

from llm_redteam.campaign_plan import (
    CampaignPlan,
    CampaignPreflight,
    RedPolicyKind,
)
from llm_redteam.campaigns.model_qualification import (
    build_artifact_qualified_campaign_policies,
)
from llm_redteam.domain import TargetClass, TargetMode
from llm_redteam.evaluation_protocol import CampaignPurpose
from llm_redteam.model_artifact import ModelArtifactIdentity
from llm_redteam.model_roles import ModelsConfig


def _models() -> ModelsConfig:
    return ModelsConfig.model_validate(
        {
            "version": 1,
            "policy": {"local_first": True, "allow_cloud_fallback": False},
            "roles": {
                "red_planner": {
                    "provider": "ollama",
                    "model": "planner:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.2,
                    "max_output_tokens": 256,
                    "fallback": [],
                },
                "red_mutator": {
                    "provider": "ollama",
                    "model": "mutator:latest",
                    "class": "local",
                    "capabilities": ["text"],
                    "temperature": 0.7,
                    "max_output_tokens": 128,
                    "fallback": [],
                },
                "judge_semantic": {
                    "provider": "ollama",
                    "model": "judge:latest",
                    "class": "local",
                    "capabilities": ["text", "reasoning"],
                    "temperature": 0.0,
                    "max_output_tokens": 256,
                    "fallback": [],
                },
            },
        }
    )


def _artifact(model: str, char: str) -> ModelArtifactIdentity:
    return ModelArtifactIdentity(
        provider_id="ollama",
        model_id=model,
        artifact_digest="sha256:" + char * 64,
        artifact_size_bytes=1024,
        local_artifact=True,
        format="gguf",
    )


def _artifacts(*, planner_char: str = "a") -> dict[tuple[str, str], ModelArtifactIdentity]:
    return {
        ("ollama", "planner:latest"): _artifact("planner:latest", planner_char),
        ("ollama", "mutator:latest"): _artifact("mutator:latest", "b"),
        ("ollama", "judge:latest"): _artifact("judge:latest", "c"),
    }


def _plan(
    *,
    purpose: CampaignPurpose = CampaignPurpose.DISCOVERY,
    red_policy: RedPolicyKind = RedPolicyKind.ADAPTIVE,
    attack_policy_fingerprint: str | None = None,
    judge_policy_fingerprint: str | None = None,
) -> CampaignPlan:
    return CampaignPlan(
        purpose=purpose,
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        budget_profile="smoke",
        red_policy=red_policy,
        replicates=1,
        attack_policy_fingerprint=attack_policy_fingerprint,
        judge_policy_fingerprint=judge_policy_fingerprint,
    )


def _preflight(
    *,
    purpose: CampaignPurpose = CampaignPurpose.DISCOVERY,
    red_policy: RedPolicyKind = RedPolicyKind.ADAPTIVE,
    required_model_roles: tuple[str, ...] = (
        "red_planner",
        "red_mutator",
        "judge_semantic",
    ),
    issues=(),
) -> CampaignPreflight:
    return CampaignPreflight(
        purpose=purpose,
        target_class=TargetClass.REASONING,
        target_mode=TargetMode.MODEL,
        budget_profile="smoke",
        red_policy=red_policy,
        selected_case_ids=("CASE-001",),
        planned_trials=1,
        minimum_target_interactions=1,
        maximum_target_interactions=3,
        multi_turn_cases=1,
        image_cases=0,
        required_model_roles=required_model_roles,
        issues=issues,
    )


def _attack_descriptor() -> dict[str, object]:
    return {
        "kind": "adaptive",
        "runtime_version": 2,
        "red_planner": {"model": "planner:latest"},
        "red_mutator": {"model": "mutator:latest"},
    }


def _judge_descriptor() -> dict[str, object]:
    return {"kind": "semantic", "implementation": "SemanticJudge", "version": 1}


def _build(
    *,
    plan: CampaignPlan | None = None,
    preflight: CampaignPreflight | None = None,
    artifacts: dict[tuple[str, str], ModelArtifactIdentity] | None = None,
):
    return build_artifact_qualified_campaign_policies(
        plan=plan or _plan(),
        preflight=preflight or _preflight(),
        models=_models(),
        artifacts=artifacts or _artifacts(),
        attack_policy_descriptor=_attack_descriptor(),
        judge_policy_descriptor=_judge_descriptor(),
    )


def test_campaign_contract_binds_all_preflight_required_model_roles() -> None:
    identity = _build()

    assert tuple(role.value for role in identity.required_model_roles) == (
        "judge_semantic",
        "red_mutator",
        "red_planner",
    )
    assert identity.red_model_role_set_sha256 is not None
    assert identity.judge_model_role_set_sha256 is not None
    assert len(identity.attack_policy_fingerprint) == 64
    assert len(identity.judge_policy_fingerprint) == 64
    assert len(identity.qualification_sha256) == 64
    assert "model_role_artifacts" in identity.attack_policy_descriptor
    assert "model_role_artifacts" in identity.judge_policy_descriptor


def test_changed_weights_under_same_tag_change_campaign_attack_identity() -> None:
    first = _build(artifacts=_artifacts(planner_char="a"))
    second = _build(artifacts=_artifacts(planner_char="d"))

    assert first.attack_policy_fingerprint != second.attack_policy_fingerprint
    assert first.judge_policy_fingerprint == second.judge_policy_fingerprint
    assert first.qualification_sha256 != second.qualification_sha256


def test_declared_discovery_fingerprint_mismatch_fails_closed() -> None:
    with pytest.raises(ValueError, match="attack_policy_fingerprint"):
        _build(plan=_plan(attack_policy_fingerprint="0" * 64))

    with pytest.raises(ValueError, match="judge_policy_fingerprint"):
        _build(plan=_plan(judge_policy_fingerprint="0" * 64))


def test_exact_declared_fingerprints_are_accepted() -> None:
    observed = _build()
    bound = _build(
        plan=_plan(
            attack_policy_fingerprint=observed.attack_policy_fingerprint,
            judge_policy_fingerprint=observed.judge_policy_fingerprint,
        )
    )

    assert bound.attack_policy_fingerprint == observed.attack_policy_fingerprint
    assert bound.judge_policy_fingerprint == observed.judge_policy_fingerprint


def test_not_ready_or_mismatched_preflight_cannot_be_qualified() -> None:
    broken = _preflight().model_copy(
        update={
            "issues": (
                {
                    "code": "TEST_BLOCK",
                    "severity": "ERROR",
                    "message": "synthetic preflight block",
                },
            )
        }
    )
    with pytest.raises(ValueError, match="preflight is not ready"):
        _build(preflight=CampaignPreflight.model_validate(broken.model_dump(mode="json")))

    mismatch = _preflight().model_copy(update={"target_mode": TargetMode.AGENT})
    with pytest.raises(ValueError, match="target identity"):
        _build(preflight=mismatch)


def test_model_backed_red_requires_both_red_roles() -> None:
    planner_only = _preflight(required_model_roles=("red_planner", "judge_semantic"))
    with pytest.raises(ValueError, match="both planner and mutator"):
        _build(preflight=planner_only)


def test_static_red_does_not_require_red_artifact_binding() -> None:
    plan = _plan(red_policy=RedPolicyKind.STATIC)
    preflight = _preflight(
        red_policy=RedPolicyKind.STATIC,
        required_model_roles=("judge_semantic",),
    )
    identity = build_artifact_qualified_campaign_policies(
        plan=plan,
        preflight=preflight,
        models=_models(),
        artifacts={
            ("ollama", "judge:latest"): _artifact("judge:latest", "c"),
        },
        attack_policy_descriptor={"kind": "static", "version": 1},
        judge_policy_descriptor=_judge_descriptor(),
    )

    assert identity.red_model_role_set_sha256 is None
    assert identity.judge_model_role_set_sha256 is not None
    assert "model_role_artifacts" not in identity.attack_policy_descriptor
    assert "model_role_artifacts" in identity.judge_policy_descriptor


def test_deterministic_static_campaign_needs_no_model_config_or_artifacts() -> None:
    identity = build_artifact_qualified_campaign_policies(
        plan=_plan(red_policy=RedPolicyKind.STATIC),
        preflight=_preflight(
            red_policy=RedPolicyKind.STATIC,
            required_model_roles=(),
        ),
        models=None,
        artifacts={},
        attack_policy_descriptor={"kind": "static", "version": 1},
        judge_policy_descriptor={"kind": "deterministic", "version": 1},
    )

    assert identity.required_model_roles == ()
    assert identity.red_model_role_set_sha256 is None
    assert identity.judge_model_role_set_sha256 is None


def test_missing_required_artifact_blocks_campaign_qualification() -> None:
    with pytest.raises(ValueError, match="verified model artifact missing"):
        _build(
            artifacts={
                ("ollama", "planner:latest"): _artifact("planner:latest", "a"),
                ("ollama", "mutator:latest"): _artifact("mutator:latest", "b"),
            }
        )
