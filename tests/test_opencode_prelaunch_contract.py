import pytest

from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_networked_sandbox import DockerNetworkedAgentProfile
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.opencode_prelaunch import (
    DockerOpenCodeNetworkedAgentProfile,
    bind_attested_opencode_launch,
    build_opencode_prelaunch_contract,
    verify_opencode_docker_process,
)
from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
    build_attested_opencode_launch_plan,
)

_IMAGE_ID = "sha256:" + "a" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "b" * 64
_PROOF = "c" * 64
_SECRET = "synthetic-secret-value"


def _runtime(**updates: object) -> OpenCodeRuntimeProfile:
    values: dict[str, object] = {
        "workspace_root": "/workspace",
        "hostname": "127.0.0.1",
        "port": 4096,
        "server_password_env": "OPENCODE_SERVER_PASSWORD",
    }
    values.update(updates)
    return OpenCodeRuntimeProfile.model_validate(values)


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _base_networked() -> DockerNetworkedAgentProfile:
    sandbox = DockerSandboxProfile(
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
    )
    return DockerNetworkedAgentProfile.compose(
        sandbox=sandbox,
        model_network=_network(),
    )


def _configured(
    runtime: OpenCodeRuntimeProfile | None = None,
) -> DockerOpenCodeNetworkedAgentProfile:
    chosen = runtime or _runtime()
    return DockerOpenCodeNetworkedAgentProfile.compose(
        sandbox=_base_networked(),
        runtime_launch=build_opencode_prelaunch_contract(chosen),
    )


def _policy(profile: DockerOpenCodeNetworkedAgentProfile) -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _attestation(
    runtime: OpenCodeRuntimeProfile,
    policy: AgentSandboxPolicy,
) -> AgentSandboxAttestation:
    return AgentSandboxAttestation(
        issuer="synthetic",
        isolation_id="docker-networked:synthetic",
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256=policy.policy_sha256,
        workspace_root_sha256=runtime.workspace_root_sha256,
        proof_sha256=_PROOF,
    )


def _inspect_payload(
    *,
    public_updates: dict[str, str] | None = None,
    secret: str = _SECRET,
    entrypoint: object = None,
) -> dict[str, object]:
    prelaunch = build_opencode_prelaunch_contract(_runtime())
    environment = dict(prelaunch.public_environment)
    environment.update(public_updates or {})
    environment["OPENCODE_SERVER_PASSWORD"] = secret
    return {
        "Config": {
            "Entrypoint": entrypoint,
            "Cmd": list(prelaunch.command),
            "WorkingDir": prelaunch.cwd,
            "Env": [f"{name}={value}" for name, value in environment.items()],
        }
    }


def test_prelaunch_contract_matches_historical_attested_plan() -> None:
    runtime = _runtime()
    prelaunch = build_opencode_prelaunch_contract(runtime)
    configured = _configured(runtime)
    policy = _policy(configured)
    plan = build_attested_opencode_launch_plan(
        runtime,
        policy,
        _attestation(runtime, policy),
    )

    binding = bind_attested_opencode_launch(
        prelaunch=prelaunch,
        sandbox_policy=policy,
        launch_plan=plan,
    )

    assert binding.prelaunch_contract_sha256 == prelaunch.contract_sha256
    assert binding.sandbox_policy_sha256 == policy.policy_sha256
    assert binding.launch_plan_sha256 == plan.launch_sha256
    assert binding.target_policy_sha256 == plan.target_policy_sha256


def test_networked_docker_command_injects_exact_prelaunch_environment() -> None:
    runtime = _runtime()
    profile = _configured(runtime)
    prelaunch = profile.runtime_launch

    command = profile.docker_run_command(
        container_name="agent-peer",
        workspace_host_path="/tmp/workspace",
        network_name="rt-model-net",
        command=prelaunch.command,
        detach=True,
    )

    image_index = command.index(_IMAGE_REF)
    before_image = command[:image_index]
    assert "--network" in before_image
    assert "rt-model-net" in before_image
    assert "--env" in before_image
    for name, value in prelaunch.public_environment.items():
        assert f"{name}={value}" in before_image
    assert "OPENCODE_SERVER_PASSWORD" in before_image
    assert not any(
        item.startswith("OPENCODE_SERVER_PASSWORD=") for item in before_image
    )
    assert command[image_index + 1 :] == prelaunch.command


def test_docker_process_state_matches_prelaunch_without_persisting_secret() -> None:
    prelaunch = build_opencode_prelaunch_contract(_runtime())

    observation = verify_opencode_docker_process(
        payload=_inspect_payload(),
        prelaunch=prelaunch,
    )

    assert observation.prelaunch_contract_sha256 == prelaunch.contract_sha256
    assert observation.entrypoint_empty is True
    assert len(observation.proof_sha256) == 64
    assert _SECRET not in observation.model_dump_json()


def test_docker_process_rejects_public_environment_drift() -> None:
    prelaunch = build_opencode_prelaunch_contract(_runtime())

    with pytest.raises(ValueError, match="OPENCODE_AUTO_SHARE"):
        verify_opencode_docker_process(
            payload=_inspect_payload(
                public_updates={"OPENCODE_AUTO_SHARE": "true"}
            ),
            prelaunch=prelaunch,
        )


def test_docker_process_rejects_missing_secret_and_entrypoint() -> None:
    prelaunch = build_opencode_prelaunch_contract(_runtime())

    with pytest.raises(ValueError, match="secret_environment"):
        verify_opencode_docker_process(
            payload=_inspect_payload(secret=""),
            prelaunch=prelaunch,
        )
    with pytest.raises(ValueError, match="entrypoint"):
        verify_opencode_docker_process(
            payload=_inspect_payload(entrypoint=["/bin/sh", "-c"]),
            prelaunch=prelaunch,
        )


def test_prelaunch_policy_has_distinct_identity_without_changing_base_profile() -> None:
    base = _base_networked()
    original_hash = base.profile_sha256
    configured = DockerOpenCodeNetworkedAgentProfile.compose(
        sandbox=base,
        runtime_launch=build_opencode_prelaunch_contract(_runtime()),
    )

    assert base.profile_sha256 == original_hash
    assert configured.profile_sha256 != base.profile_sha256


def test_runtime_change_changes_prelaunch_and_enforcement_identity() -> None:
    first = _configured(_runtime(port=4096))
    second = _configured(_runtime(port=4097))

    assert first.runtime_launch.contract_sha256 != second.runtime_launch.contract_sha256
    assert first.profile_sha256 != second.profile_sha256


def test_different_command_is_rejected_before_docker_launch() -> None:
    profile = _configured()

    with pytest.raises(ValueError, match="differs from prelaunch"):
        profile.docker_run_command(
            container_name="agent-peer",
            workspace_host_path="/tmp/workspace",
            network_name="rt-model-net",
            command=("opencode", "serve", "--different"),
            detach=True,
        )


def test_post_launch_plan_drift_is_rejected() -> None:
    runtime = _runtime()
    prelaunch = build_opencode_prelaunch_contract(runtime)
    configured = _configured(runtime)
    policy = _policy(configured)
    plan = build_attested_opencode_launch_plan(
        runtime,
        policy,
        _attestation(runtime, policy),
    )
    drifted = plan.model_copy(
        update={"public_environment": {"OPENCODE_AUTO_SHARE": "true"}}
    )

    with pytest.raises(ValueError, match="public_environment"):
        bind_attested_opencode_launch(
            prelaunch=prelaunch,
            sandbox_policy=policy,
            launch_plan=drifted,
        )
