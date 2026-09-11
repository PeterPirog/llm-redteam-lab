import asyncio
import json

import pytest

from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    AttestedOpenCodeTarget,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
    build_attested_opencode_launch_plan,
)
from llm_redteam.targets.opencode import OpenCodeConfig, OpenCodeTarget


def _profile(**updates: object) -> OpenCodeRuntimeProfile:
    values: dict[str, object] = {
        "workspace_root": r"D:\\redteam\\fixture-workspace",
        "hostname": "127.0.0.1",
        "port": 4096,
        "shell_allowlist": ("python *", "pytest *", "git status *", "git diff *"),
        "server_password_env": "OPENCODE_RT_PASSWORD",
    }
    values.update(updates)
    return OpenCodeRuntimeProfile.model_validate(values)


def _policy(**updates: object) -> AgentSandboxPolicy:
    values: dict[str, object] = {
        "enforcement_kind": SandboxEnforcementKind.TRUSTED_HARNESS,
        "disposable_workspace": True,
        "external_network_denied": True,
        "git_publication_denied": True,
        "allowed_network_endpoints": (
            "http://127.0.0.1:11434",
            "http://127.0.0.1:4096",
        ),
    }
    values.update(updates)
    return AgentSandboxPolicy.model_validate(values)


def _attestation(
    profile: OpenCodeRuntimeProfile,
    policy: AgentSandboxPolicy,
    **updates: object,
) -> AgentSandboxAttestation:
    values: dict[str, object] = {
        "issuer": "llm-redteam-trusted-test-harness",
        "isolation_id": "synthetic-isolation-1",
        "runtime_profile_sha256": profile.profile_sha256,
        "sandbox_policy_sha256": policy.policy_sha256,
        "workspace_root_sha256": profile.workspace_root_sha256,
        "proof_sha256": "f" * 64,
    }
    values.update(updates)
    return AgentSandboxAttestation.model_validate(values)


def _plan(
    profile: OpenCodeRuntimeProfile | None = None,
    policy: AgentSandboxPolicy | None = None,
    **attestation_updates: object,
):
    resolved_profile = profile or _profile()
    resolved_policy = policy or _policy()
    return build_attested_opencode_launch_plan(
        resolved_profile,
        resolved_policy,
        _attestation(resolved_profile, resolved_policy, **attestation_updates),
    )


def _target_config(**updates: object) -> OpenCodeConfig:
    values: dict[str, object] = {
        "id": "opencode-attested-test",
        "base_url": "http://127.0.0.1:4096",
        "model_provider_id": "ollama",
        "model_id": "local-test-model",
        "workspace_root": r"D:\\redteam\\fixture-workspace",
        "application_version": "synthetic-test",
        "password_env": "OPENCODE_RT_PASSWORD",
    }
    values.update(updates)
    return OpenCodeConfig.model_validate(values)


def test_runtime_profile_generates_deny_by_default_local_config() -> None:
    profile = _profile()
    document = json.loads(profile.config_json())

    assert document["share"] == "disabled"
    assert document["autoupdate"] is False
    permission = document["permission"]
    assert permission["*"] == "deny"
    assert permission["external_directory"] == "deny"
    assert permission["webfetch"] == "deny"
    assert permission["websearch"] == "deny"
    assert permission["task"] == "deny"
    assert permission["bash"]["*"] == "deny"
    assert permission["bash"]["pytest *"] == "allow"
    assert permission["read"]["*.env"] == "deny"


def test_launch_plan_requires_restricted_stable_sandbox_policy() -> None:
    profile = _profile()

    for field in (
        "external_network_denied",
        "git_publication_denied",
        "disposable_workspace",
    ):
        policy = _policy(**{field: False})
        attestation = _attestation(profile, policy)
        with pytest.raises(ValueError, match=field):
            build_attested_opencode_launch_plan(profile, policy, attestation)


def test_launch_plan_is_pure_loopback_and_contains_no_secret_value() -> None:
    plan = _plan()

    assert plan.command == (
        "opencode",
        "--pure",
        "serve",
        "--hostname",
        "127.0.0.1",
        "--port",
        "4096",
    )
    assert plan.required_secret_env_names == ("OPENCODE_RT_PASSWORD",)
    assert plan.public_environment["OPENCODE_AUTO_SHARE"] == "false"
    assert plan.public_environment["OPENCODE_DISABLE_AUTOUPDATE"] == "true"
    serialized = plan.model_dump_json()
    assert "synthetic-secret-value" not in serialized


def test_profile_rejects_non_loopback_or_explicit_network_shell_rules() -> None:
    with pytest.raises(ValueError, match="loopback"):
        _profile(hostname="0.0.0.0")

    with pytest.raises(ValueError, match="network tools"):
        _profile(shell_allowlist=("curl *",))

    with pytest.raises(ValueError, match="publication"):
        _profile(shell_allowlist=("git push *",))


def test_sandbox_policy_rejects_nonlocal_allowlisted_endpoint() -> None:
    with pytest.raises(ValueError, match="loopback"):
        _policy(allowed_network_endpoints=("https://example.com",))


def test_per_run_attestation_does_not_change_blue_target_identity() -> None:
    profile = _profile()
    policy = _policy()
    first_plan = _plan(profile, policy)
    second_plan = _plan(
        profile,
        policy,
        proof_sha256="e" * 64,
        isolation_id="synthetic-isolation-2",
    )

    first = AttestedOpenCodeTarget(OpenCodeTarget(_target_config()), first_plan)
    second = AttestedOpenCodeTarget(OpenCodeTarget(_target_config()), second_plan)

    try:
        assert first_plan.launch_sha256 != second_plan.launch_sha256
        assert first.identity.configuration_hash == second.identity.configuration_hash
        assert "runtime_attested" in first.identity.capabilities
    finally:
        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_security_policy_change_changes_blue_target_identity() -> None:
    profile = _profile()
    first_policy = _policy()
    second_policy = _policy(
        allowed_network_endpoints=("http://127.0.0.1:4096",),
    )
    first = AttestedOpenCodeTarget(
        OpenCodeTarget(_target_config()),
        _plan(profile, first_policy),
    )
    second = AttestedOpenCodeTarget(
        OpenCodeTarget(_target_config()),
        _plan(profile, second_policy),
    )

    try:
        assert first.identity.configuration_hash != second.identity.configuration_hash
    finally:
        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_attested_target_fails_closed_on_workspace_or_endpoint_mismatch() -> None:
    plan = _plan()

    with pytest.raises(ValueError, match="workspace"):
        AttestedOpenCodeTarget(
            OpenCodeTarget(_target_config(workspace_root=r"D:\\other")),
            plan,
        )

    with pytest.raises(ValueError, match="port"):
        AttestedOpenCodeTarget(
            OpenCodeTarget(_target_config(base_url="http://127.0.0.1:4999")),
            plan,
        )


def test_attestation_must_bind_exact_runtime_profile_and_sandbox_policy() -> None:
    profile = _profile()
    policy = _policy()
    stale = _attestation(profile, policy)

    changed_profile = _profile(shell_allowlist=("pytest *",))
    with pytest.raises(ValueError, match="runtime profile"):
        build_attested_opencode_launch_plan(changed_profile, policy, stale)

    changed_policy = _policy(allowed_network_endpoints=("http://127.0.0.1:4096",))
    with pytest.raises(ValueError, match="sandbox policy"):
        build_attested_opencode_launch_plan(profile, changed_policy, stale)
