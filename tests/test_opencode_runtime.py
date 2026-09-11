import json

import pytest

from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
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


def _attestation(
    profile: OpenCodeRuntimeProfile,
    **updates: object,
) -> AgentSandboxAttestation:
    values: dict[str, object] = {
        "issuer": "llm-redteam-trusted-test-harness",
        "enforcement_kind": SandboxEnforcementKind.TRUSTED_HARNESS,
        "isolation_id": "synthetic-isolation-1",
        "runtime_profile_sha256": profile.profile_sha256,
        "workspace_root_sha256": profile.workspace_root_sha256,
        "proof_sha256": "f" * 64,
        "disposable_workspace": True,
        "external_network_denied": True,
        "git_publication_denied": True,
        "allowed_network_endpoints": (
            "http://127.0.0.1:11434",
            "http://127.0.0.1:4096",
        ),
    }
    values.update(updates)
    return AgentSandboxAttestation.model_validate(values)


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


def test_launch_plan_requires_independent_containment_attestation() -> None:
    profile = _profile()

    with pytest.raises(ValueError, match="external_network_denied"):
        build_attested_opencode_launch_plan(
            profile,
            _attestation(profile, external_network_denied=False),
        )

    with pytest.raises(ValueError, match="git_publication_denied"):
        build_attested_opencode_launch_plan(
            profile,
            _attestation(profile, git_publication_denied=False),
        )

    with pytest.raises(ValueError, match="disposable_workspace"):
        build_attested_opencode_launch_plan(
            profile,
            _attestation(profile, disposable_workspace=False),
        )


def test_launch_plan_is_pure_loopback_and_contains_no_secret_value() -> None:
    profile = _profile()
    plan = build_attested_opencode_launch_plan(profile, _attestation(profile))

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


def test_attestation_rejects_nonlocal_allowlisted_endpoint() -> None:
    profile = _profile()

    with pytest.raises(ValueError, match="loopback"):
        _attestation(
            profile,
            allowed_network_endpoints=("https://example.com",),
        )


def test_attested_target_identity_binds_launch_and_sandbox_policy() -> None:
    profile = _profile()
    first_plan = build_attested_opencode_launch_plan(profile, _attestation(profile))
    second_plan = build_attested_opencode_launch_plan(
        profile,
        _attestation(profile, proof_sha256="e" * 64, isolation_id="synthetic-isolation-2"),
    )

    first = AttestedOpenCodeTarget(OpenCodeTarget(_target_config()), first_plan)
    second = AttestedOpenCodeTarget(OpenCodeTarget(_target_config()), second_plan)

    try:
        assert first.identity.configuration_hash != second.identity.configuration_hash
        assert "runtime_attested" in first.identity.capabilities
        assert first.identity.model == second.identity.model
    finally:
        import asyncio

        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_attested_target_fails_closed_on_workspace_or_endpoint_mismatch() -> None:
    profile = _profile()
    plan = build_attested_opencode_launch_plan(profile, _attestation(profile))

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


def test_attestation_must_bind_exact_runtime_profile() -> None:
    profile = _profile()
    changed = _profile(shell_allowlist=("pytest *",))
    stale = _attestation(profile)

    with pytest.raises(ValueError, match="runtime profile"):
        build_attested_opencode_launch_plan(changed, stale)
