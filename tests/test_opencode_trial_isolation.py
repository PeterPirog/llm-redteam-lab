import base64
import json
from hashlib import sha256
from pathlib import Path

import pytest

from llm_redteam.docker_model_network import (
    DockerIsolatedModelNetworkAttestation,
    DockerIsolatedModelNetworkProfile,
)
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_networked_sandbox import DockerNetworkedAgentProfile
from llm_redteam.docker_networked_supervisor import DockerNetworkedAgentLease
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.docker_supervisor import CommandResult
from llm_redteam.opencode_prelaunch import (
    DockerOpenCodeNetworkedAgentProfile,
    build_opencode_prelaunch_contract,
)
from llm_redteam.opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    McpFixtureBridgeProfile,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)
from llm_redteam.opencode_trial_isolation import (
    DockerOpenCodeTrialLeaseProvider,
    FilesystemDisposableWorkspaceProvider,
)
from llm_redteam.target_trial_isolation import (
    TargetIsolationLevel,
    validate_target_trial_lease,
)
from llm_redteam.targets.base import SessionMode
from llm_redteam.targets.opencode import OpenCodeConfig

_IMAGE_ID = "sha256:" + "1" * 64
_IMAGE_REF = "synthetic/opencode@sha256:" + "2" * 64
_CONTAINER_ID = "a" * 64
_MODEL_PEER_ID_HASH = "b" * 64
_NETWORK_ID_HASH = "c" * 64
_VERSION = "1.2.3"


def _runtime(*, mcp: bool = False) -> OpenCodeRuntimeProfile:
    bridge = (
        McpFixtureBridgeProfile(
            context_file_path="/control/fixture.json",
            context_hash_file_path="/control/fixture.sha256",
        )
        if mcp
        else None
    )
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        hostname="127.0.0.1",
        port=4096,
        server_password_env="OPENCODE_SERVER_PASSWORD",
        mcp_fixture_bridge=bridge,
    )


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _docker_profile(
    runtime: OpenCodeRuntimeProfile,
) -> DockerOpenCodeNetworkedAgentProfile:
    sandbox = DockerSandboxProfile(
        image_ref=_IMAGE_REF,
        image_id=_IMAGE_ID,
        memory_limit_bytes=512 * 1024 * 1024,
        pids_limit=128,
        cpus=2.0,
    )
    networked = DockerNetworkedAgentProfile.compose(
        sandbox=sandbox,
        model_network=_network(),
    )
    return DockerOpenCodeNetworkedAgentProfile.compose(
        sandbox=networked,
        runtime_launch=build_opencode_prelaunch_contract(runtime),
    )


def _policy(profile: DockerOpenCodeNetworkedAgentProfile) -> AgentSandboxPolicy:
    return AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )


def _config() -> OpenCodeConfig:
    return OpenCodeConfig(
        id="opencode-local-agent",
        base_url="http://127.0.0.1:4096",
        model_provider_id="ollama",
        model_id="qwen-local",
        workspace_root="/workspace",
        application_version=_VERSION,
        password_env="OPENCODE_SERVER_PASSWORD",
    )


def _network_lease(profile: DockerIsolatedModelNetworkProfile) -> DockerModelNetworkLease:
    return DockerModelNetworkLease(
        network_name="llmrt-model-network",
        network_id_sha256=_NETWORK_ID_HASH,
        network_profile_sha256=profile.profile_sha256,
        create_command_sha256="d" * 64,
        engine=DockerEngineVersionObservation(
            server_version="28.0.0",
            major=28,
            minor=0,
            patch=0,
            command_sha256="e" * 64,
        ),
    )


def _agent_lease(
    *,
    runtime: OpenCodeRuntimeProfile,
    policy: AgentSandboxPolicy,
    network: DockerIsolatedModelNetworkProfile,
    container_name: str,
) -> DockerNetworkedAgentLease:
    container_hash = sha256(_CONTAINER_ID.encode()).hexdigest()
    sandbox_attestation = AgentSandboxAttestation(
        issuer="synthetic-agent-supervisor",
        isolation_id=f"docker-networked:{container_hash}",
        runtime_profile_sha256=runtime.profile_sha256,
        sandbox_policy_sha256=policy.policy_sha256,
        workspace_root_sha256=runtime.workspace_root_sha256,
        proof_sha256="f" * 64,
    )
    network_attestation = DockerIsolatedModelNetworkAttestation(
        issuer="synthetic-network-supervisor",
        network_profile_sha256=network.profile_sha256,
        network_id_sha256=_NETWORK_ID_HASH,
        network_name_sha256="0" * 64,
        agent_container_id_sha256=container_hash,
        model_peer_container_id_sha256=_MODEL_PEER_ID_HASH,
        model_endpoint_origin_sha256=sha256(
            network.model_endpoint_origin.encode()
        ).hexdigest(),
        network_inspection_sha256="3" * 64,
        agent_membership_sha256="4" * 64,
        model_membership_sha256="5" * 64,
    )
    return DockerNetworkedAgentLease(
        container_name=container_name,
        container_id_sha256=container_hash,
        launch_command_sha256="6" * 64,
        network_id_sha256=_NETWORK_ID_HASH,
        sandbox_attestation=sandbox_attestation,
        network_attestation=network_attestation,
    )


class _FakeAgentSupervisor:
    def __init__(
        self,
        *,
        runtime: OpenCodeRuntimeProfile,
        policy: AgentSandboxPolicy,
        network: DockerIsolatedModelNetworkProfile,
    ) -> None:
        self.runtime = runtime
        self.policy = policy
        self.network = network
        self.launches: list[dict[str, object]] = []
        self.releases = 0
        self.fail_release = False

    def launch(self, **kwargs):
        self.launches.append(kwargs)
        return _agent_lease(
            runtime=self.runtime,
            policy=self.policy,
            network=self.network,
            container_name=kwargs["container_name"],
        )

    def release(self, lease: DockerNetworkedAgentLease) -> None:
        assert lease.container_id_sha256 == sha256(_CONTAINER_ID.encode()).hexdigest()
        if self.fail_release:
            raise RuntimeError("synthetic container teardown failure")
        self.releases += 1


class _FakeRunner:
    def __init__(
        self,
        *,
        runtime: OpenCodeRuntimeProfile,
        version: str = _VERSION,
    ) -> None:
        self.runtime = runtime
        self.version = version
        self.commands: list[tuple[str, ...]] = []

    def run(self, command: tuple[str, ...], *, timeout_seconds: float) -> CommandResult:
        del timeout_seconds
        self.commands.append(command)
        if command[:4] == ("docker", "inspect", "--type", "container"):
            prelaunch = build_opencode_prelaunch_contract(self.runtime)
            environment = [
                f"{name}={value}" for name, value in prelaunch.public_environment.items()
            ]
            environment.append("OPENCODE_SERVER_PASSWORD=synthetic-secret")
            payload = [
                {
                    "Id": _CONTAINER_ID,
                    "Config": {
                        "Entrypoint": None,
                        "Cmd": list(prelaunch.command),
                        "WorkingDir": prelaunch.cwd,
                        "Env": environment,
                    },
                }
            ]
            return CommandResult(
                returncode=0,
                stdout=json.dumps(payload),
                stderr="",
            )
        if command[:2] == ("docker", "exec"):
            body = json.dumps({"healthy": True, "version": self.version}).encode()
            envelope = {
                "status": 200,
                "body_b64": base64.b64encode(body).decode(),
            }
            return CommandResult(
                returncode=0,
                stdout=json.dumps(envelope),
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command}")


def _provider(tmp_path: Path, *, health_version: str = _VERSION):
    runtime = _runtime()
    network = _network()
    profile = _docker_profile(runtime)
    policy = _policy(profile)
    runner = _FakeRunner(runtime=runtime, version=health_version)
    supervisor = _FakeAgentSupervisor(
        runtime=runtime,
        policy=policy,
        network=network,
    )
    workspaces = FilesystemDisposableWorkspaceProvider(tmp_path / "workspaces")
    provider = DockerOpenCodeTrialLeaseProvider(
        provider_id="synthetic-opencode-trials",
        workspace_provider=workspaces,
        agent_supervisor=supervisor,
        runner=runner,
        docker_profile=profile,
        model_network_profile=network,
        network_lease=_network_lease(network),
        model_peer_container_id_sha256=_MODEL_PEER_ID_HASH,
        runtime_profile=runtime,
        sandbox_policy=policy,
        opencode_config=_config(),
        health_attempts=1,
        health_retry_seconds=0,
    )
    return provider, supervisor, runner, workspaces


def test_filesystem_workspace_provider_creates_unique_empty_and_removes_it(
    tmp_path: Path,
) -> None:
    provider = FilesystemDisposableWorkspaceProvider(tmp_path / "root")
    first = provider.acquire(trial_id="trial-a")
    second = provider.acquire(trial_id="trial-b")

    assert first.workspace_id_hash != second.workspace_id_hash
    assert Path(first.host_path).is_dir()
    assert list(Path(first.host_path).iterdir()) == []
    assert Path(second.host_path).is_dir()

    first_release = provider.release(first)
    second_release = provider.release(second)
    assert first_release.cleanup_complete is True
    assert second_release.cleanup_complete is True
    assert not Path(first.host_path).exists()
    assert not Path(second.host_path).exists()


def test_disposable_provider_returns_valid_fresh_agent_lease(tmp_path: Path) -> None:
    provider, supervisor, runner, _ = _provider(tmp_path)

    lease = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="attack-1",
    )

    validate_target_trial_lease(
        lease,
        expected_identity=provider.declared_target.identity,
        session_mode=SessionMode.TARGET_MANAGED,
    )
    assert lease.attestation.isolation_level == TargetIsolationLevel.DISPOSABLE_SANDBOX
    assert "runtime_attested" in lease.target.identity.capabilities
    assert "runtime_health_verified" in lease.target.identity.capabilities
    assert supervisor.launches
    assert any(command[:2] == ("docker", "exec") for command in runner.commands)

    released = provider.release(lease)
    assert released.cleanup_complete is True
    assert supervisor.releases == 1


def test_each_agent_trial_gets_distinct_workspace_container_and_lease(tmp_path: Path) -> None:
    provider, supervisor, _, _ = _provider(tmp_path)

    first = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="attack-1",
    )
    first_workspace = supervisor.launches[-1]["workspace_host_path"]
    second = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="attack-2",
    )
    second_workspace = supervisor.launches[-1]["workspace_host_path"]

    assert first.attestation.lease_id_hash != second.attestation.lease_id_hash
    assert first_workspace != second_workspace
    assert supervisor.launches[0]["container_name"] != supervisor.launches[1]["container_name"]

    assert provider.release(first).cleanup_complete is True
    assert provider.release(second).cleanup_complete is True


def test_health_version_drift_fails_before_lease_and_cleans_resources(tmp_path: Path) -> None:
    provider, supervisor, _, _ = _provider(tmp_path, health_version="9.9.9")

    with pytest.raises(RuntimeError, match="health/version admission"):
        provider.acquire(
            expected_identity=provider.declared_target.identity,
            trial_id="wrong-version",
        )

    assert supervisor.releases == 1
    workspace_root = tmp_path / "workspaces"
    assert workspace_root.is_dir()
    assert list(workspace_root.iterdir()) == []


def test_container_teardown_failure_preserves_workspace_and_reports_incomplete(
    tmp_path: Path,
) -> None:
    provider, supervisor, _, _ = _provider(tmp_path)
    lease = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="cleanup-failure",
    )
    workspace = Path(supervisor.launches[-1]["workspace_host_path"])
    supervisor.fail_release = True

    first_release = provider.release(lease)

    assert first_release.cleanup_complete is False
    assert workspace.exists()

    supervisor.fail_release = False
    second_release = provider.release(lease)
    assert second_release.cleanup_complete is True
    assert not workspace.exists()


def test_provider_rejects_mcp_until_compound_fixture_mount_is_implemented(
    tmp_path: Path,
) -> None:
    runtime = _runtime(mcp=True)
    network = _network()
    profile = _docker_profile(runtime)
    policy = _policy(profile)

    with pytest.raises(ValueError, match="compound fixture/target isolation"):
        DockerOpenCodeTrialLeaseProvider(
            provider_id="no-mcp-yet",
            workspace_provider=FilesystemDisposableWorkspaceProvider(tmp_path / "workspaces"),
            agent_supervisor=_FakeAgentSupervisor(
                runtime=runtime,
                policy=policy,
                network=network,
            ),
            runner=_FakeRunner(runtime=runtime),
            docker_profile=profile,
            model_network_profile=network,
            network_lease=_network_lease(network),
            model_peer_container_id_sha256=_MODEL_PEER_ID_HASH,
            runtime_profile=runtime,
            sandbox_policy=policy,
            opencode_config=_config(),
        )
