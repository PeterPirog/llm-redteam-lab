import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

import llm_redteam.opencode_trial_isolation as isolation_module
from llm_redteam.disposable_workspace import DisposableWorkspaceSupervisor
from llm_redteam.docker_model_network import DockerIsolatedModelNetworkProfile
from llm_redteam.docker_model_network_supervisor import (
    DockerEngineVersionObservation,
    DockerModelNetworkLease,
)
from llm_redteam.docker_networked_opencode_profile import (
    DockerNetworkedOpenCodeAgentProfile,
)
from llm_redteam.docker_sandbox import DockerSandboxProfile
from llm_redteam.domain import EvidenceKind, TargetMode
from llm_redteam.opencode_model_peer import OpenCodeModelPeerBinding
from llm_redteam.opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from llm_redteam.opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeRuntimeProfile,
    SandboxEnforcementKind,
)
from llm_redteam.state_verifiers import RelativePathStateVerifier
from llm_redteam.target_trial_isolation import (
    TargetIsolationLevel,
    validate_target_trial_lease,
)
from llm_redteam.targets.base import SessionMode, TargetResponse
from llm_redteam.targets.opencode import OpenCodeConfig

_IMAGE_REF = "synthetic/opencode@sha256:" + "a" * 64
_IMAGE_ID = "sha256:" + "b" * 64
_MODEL_PEER_ID = "c" * 64


class FakeRunner:
    def run(self, argv: tuple[str, ...], *, timeout_seconds: float):
        raise AssertionError(f"unexpected direct Docker command: {argv}, {timeout_seconds}")


class FakeRuntimeSupervisor:
    def __init__(self) -> None:
        self.launches: list[dict[str, object]] = []
        self.releases: list[object] = []
        self.fail_release = False

    def launch(self, **kwargs):
        self.launches.append(kwargs)
        ordinal = len(self.launches)
        return SimpleNamespace(
            agent=SimpleNamespace(
                container_name=kwargs["container_name"],
                container_id_sha256=f"{ordinal:064x}",
            ),
            launch_plan=SimpleNamespace(),
            health=SimpleNamespace(),
            proof_sha256=f"{ordinal + 10:064x}",
        )

    def release(self, lease) -> None:
        if self.fail_release:
            raise RuntimeError("synthetic runtime release failure")
        self.releases.append(lease)


class FakeTarget:
    def __init__(self, identity) -> None:
        self._identity = identity
        self.closed = False

    @property
    def identity(self):
        return self._identity

    async def execute(self, request):
        del request
        return TargetResponse(text="synthetic")

    async def aclose(self) -> None:
        self.closed = True


def _network() -> DockerIsolatedModelNetworkProfile:
    return DockerIsolatedModelNetworkProfile(
        model_endpoint_host="model-peer",
        model_endpoint_port=11434,
    )


def _runtime() -> OpenCodeRuntimeProfile:
    return OpenCodeRuntimeProfile(
        workspace_root="/workspace",
        server_password_env="OPENCODE_SERVER_PASSWORD",
    )


def _launch_policy(
    network: DockerIsolatedModelNetworkProfile,
    runtime: OpenCodeRuntimeProfile,
) -> OpenCodeNetworkedLaunchPolicy:
    return OpenCodeNetworkedLaunchPolicy(
        runtime=runtime,
        model_binding=OpenCodeModelPeerBinding.from_network(
            network=network,
            provider_id="ollama",
            model_id="qwen-local",
        ),
    )


def _docker_profile(
    network: DockerIsolatedModelNetworkProfile,
    launch: OpenCodeNetworkedLaunchPolicy,
) -> DockerNetworkedOpenCodeAgentProfile:
    return DockerNetworkedOpenCodeAgentProfile.compose(
        sandbox=DockerSandboxProfile(
            image_ref=_IMAGE_REF,
            image_id=_IMAGE_ID,
            container_workspace="/workspace",
            memory_limit_bytes=512 * 1024 * 1024,
            pids_limit=128,
            cpus=2.0,
        ),
        model_network=network,
        launch_policy=launch,
    )


def _network_lease(network: DockerIsolatedModelNetworkProfile) -> DockerModelNetworkLease:
    return DockerModelNetworkLease(
        network_name="rt-model-network",
        network_id_sha256="1" * 64,
        network_profile_sha256=network.profile_sha256,
        create_command_sha256="2" * 64,
        engine=DockerEngineVersionObservation(
            server_version="28.0.0",
            major=28,
            minor=0,
            patch=0,
            command_sha256="3" * 64,
        ),
    )


def _config() -> OpenCodeConfig:
    return OpenCodeConfig(
        id="isolated-opencode",
        base_url="http://127.0.0.1:4096",
        model_provider_id="ollama",
        model_id="qwen-local",
        workspace_root="/workspace",
        application_version="1.2.3-test",
        password_env="OPENCODE_SERVER_PASSWORD",
    )


def _provider(
    tmp_path: Path,
    *,
    measurement_binding: str | None = None,
    state_verifier_factory=None,
    state_verifier_policy_sha256: str | None = None,
):
    template = tmp_path / "template"
    sandbox_root = tmp_path / "sandboxes"
    template.mkdir(parents=True)
    (template / "README.md").write_text("synthetic\n", encoding="utf-8")
    workspace = DisposableWorkspaceSupervisor(
        template_root=template,
        sandbox_root=sandbox_root,
    )
    network = _network()
    runtime = _runtime()
    launch = _launch_policy(network, runtime)
    docker_profile = _docker_profile(network, launch)
    policy = AgentSandboxPolicy(
        enforcement_kind=SandboxEnforcementKind.DOCKER,
        enforcement_profile_sha256=docker_profile.profile_sha256,
        disposable_workspace=True,
        external_network_denied=True,
        git_publication_denied=True,
    )
    runtime_supervisor = FakeRuntimeSupervisor()
    provider = isolation_module.DockerOpenCodeTrialLeaseProvider(
        provider_id="synthetic-provider",
        workspace_supervisor=workspace,
        runtime_supervisor=runtime_supervisor,
        runner=FakeRunner(),
        docker_profile=docker_profile,
        launch_policy=launch,
        model_network_profile=network,
        network_lease=_network_lease(network),
        model_peer_container_id_sha256=_MODEL_PEER_ID,
        runtime_profile=runtime,
        sandbox_policy=policy,
        opencode_config=_config(),
        target_measurement_binding_sha256=measurement_binding,
        state_verifier_factory=state_verifier_factory,
        state_verifier_policy_sha256=state_verifier_policy_sha256,
    )
    return provider, runtime_supervisor, workspace


def _install_fake_target(monkeypatch, identity, observed: list[FakeTarget]) -> None:
    def fake_builder(**kwargs):
        del kwargs
        return SimpleNamespace(identity=identity)

    def fake_health_gate(target, health):
        del target, health
        result = FakeTarget(identity)
        observed.append(result)
        return result

    monkeypatch.setattr(
        isolation_module,
        "build_attested_docker_exec_opencode_target",
        fake_builder,
    )
    monkeypatch.setattr(isolation_module, "HealthGatedOpenCodeTarget", fake_health_gate)


def test_declared_target_is_agent_and_direct_execution_is_fail_closed(tmp_path: Path) -> None:
    provider, _, _ = _provider(tmp_path)

    assert provider.isolation_level == TargetIsolationLevel.DISPOSABLE_SANDBOX
    assert provider.declared_target.identity.target_mode == TargetMode.AGENT
    response = asyncio.run(provider.declared_target.execute(SimpleNamespace()))
    assert response.error_kind == "isolation:disposable_trial_lease_required"


def test_declared_target_identity_binds_exact_measurement_configuration(
    tmp_path: Path,
) -> None:
    unbound, _, _ = _provider(tmp_path / "unbound")
    binding = "d" * 64
    bound, _, _ = _provider(tmp_path / "bound", measurement_binding=binding)

    assert (
        bound.declared_target.identity.configuration_hash
        != unbound.declared_target.identity.configuration_hash
    )
    assert "measurement_identity_bound" in bound.declared_target.identity.capabilities
    assert bound.target_measurement_binding_sha256 == binding



def test_acquire_returns_valid_disposable_lease_with_fresh_workspace(
    tmp_path: Path, monkeypatch
) -> None:
    provider, runtime_supervisor, _ = _provider(tmp_path)
    targets: list[FakeTarget] = []
    _install_fake_target(monkeypatch, provider.declared_target.identity, targets)

    lease = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="trial-1",
    )

    assert lease.attestation.isolation_level == TargetIsolationLevel.DISPOSABLE_SANDBOX
    assert lease.attestation.control_plane_independent is True
    assert len(lease.attestation.fresh_state_proof_hash) == 64
    validate_target_trial_lease(
        lease,
        expected_identity=provider.declared_target.identity,
        session_mode=SessionMode.TARGET_MANAGED,
    )
    assert len(runtime_supervisor.launches) == 1
    workspace_path = Path(str(runtime_supervisor.launches[0]["workspace_host_path"]))
    assert workspace_path.is_dir()
    assert (workspace_path / "README.md").read_text(encoding="utf-8") == "synthetic\n"


def test_acquire_attaches_independent_verifier_to_fresh_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace_ref: list[Path] = []
    closed: list[bool] = []

    class MutatingTarget:
        def __init__(self, identity) -> None:
            self._identity = identity

        @property
        def identity(self):
            return self._identity

        async def execute(self, request):
            del request
            assert workspace_ref
            (workspace_ref[0] / "RT_FORBIDDEN_MARKER.txt").write_text(
                "synthetic forbidden effect",
                encoding="utf-8",
            )
            return TargetResponse(text="synthetic")

        async def aclose(self) -> None:
            closed.append(True)

    policy_sha = "e" * 64

    def verifier_factory(workspace_path: Path):
        workspace_ref.append(workspace_path)
        return (
            RelativePathStateVerifier(
                workspace_path,
                relative_paths=("RT_FORBIDDEN_MARKER.txt",),
                verifier_id="hal-smoke-marker-v1",
            ),
        )

    provider, runtime_supervisor, _ = _provider(
        tmp_path,
        state_verifier_factory=verifier_factory,
        state_verifier_policy_sha256=policy_sha,
    )

    def fake_builder(**kwargs):
        del kwargs
        return SimpleNamespace(identity=provider.declared_target.identity)

    def fake_health_gate(target, health):
        del target, health
        return MutatingTarget(provider.declared_target.identity)

    monkeypatch.setattr(
        isolation_module,
        "build_attested_docker_exec_opencode_target",
        fake_builder,
    )
    monkeypatch.setattr(isolation_module, "HealthGatedOpenCodeTarget", fake_health_gate)

    lease = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="trial-state-verified",
    )
    response = asyncio.run(lease.target.execute(SimpleNamespace()))

    state_evidence = [
        item for item in response.evidence if item.kind == EvidenceKind.SYSTEM_STATE
    ]
    assert len(state_evidence) == 1
    assert state_evidence[0].data["state"] == "observed"
    assert workspace_ref[0] == Path(
        str(runtime_supervisor.launches[0]["workspace_host_path"])
    )
    assert provider.state_verifier_policy_sha256 == policy_sha

    release = asyncio.run(provider.release_async(lease))
    assert release.cleanup_complete is True
    assert closed == [True]


def test_state_verifier_policy_changes_provider_fingerprint(tmp_path: Path) -> None:
    def factory(workspace_path: Path):
        return (
            RelativePathStateVerifier(
                workspace_path,
                relative_paths=("RT_FORBIDDEN_MARKER.txt",),
            ),
        )

    first, _, _ = _provider(
        tmp_path / "first",
        state_verifier_factory=factory,
        state_verifier_policy_sha256="d" * 64,
    )
    second, _, _ = _provider(
        tmp_path / "second",
        state_verifier_factory=factory,
        state_verifier_policy_sha256="e" * 64,
    )

    assert first.provider_fingerprint != second.provider_fingerprint


def test_state_verifier_factory_and_policy_must_be_supplied_together(
    tmp_path: Path,
) -> None:
    def factory(workspace_path: Path):
        return (
            RelativePathStateVerifier(
                workspace_path,
                relative_paths=("RT_FORBIDDEN_MARKER.txt",),
            ),
        )

    with pytest.raises(ValueError, match="supplied together"):
        _provider(
            tmp_path / "factory-only",
            state_verifier_factory=factory,
        )

    with pytest.raises(ValueError, match="supplied together"):
        _provider(
            tmp_path / "policy-only",
            state_verifier_policy_sha256="e" * 64,
        )


def test_release_async_closes_target_then_removes_runtime_and_workspace(
    tmp_path: Path, monkeypatch
) -> None:
    provider, runtime_supervisor, _ = _provider(tmp_path)
    targets: list[FakeTarget] = []
    _install_fake_target(monkeypatch, provider.declared_target.identity, targets)
    lease = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="trial-release",
    )
    workspace_path = Path(str(runtime_supervisor.launches[0]["workspace_host_path"]))

    release = asyncio.run(provider.release_async(lease))

    assert release.cleanup_complete is True
    assert release.lease_id_hash == lease.attestation.lease_id_hash
    assert targets[0].closed is True
    assert len(runtime_supervisor.releases) == 1
    assert not workspace_path.exists()


def test_identity_mismatch_after_runtime_launch_fails_and_cleans_containment(
    tmp_path: Path, monkeypatch
) -> None:
    provider, runtime_supervisor, _ = _provider(tmp_path)
    wrong_identity = provider.declared_target.identity.model_copy(
        update={"configuration_hash": "f" * 64}
    )
    targets: list[FakeTarget] = []
    _install_fake_target(monkeypatch, wrong_identity, targets)

    with pytest.raises(ValueError, match="differs from declaration"):
        provider.acquire(
            expected_identity=provider.declared_target.identity,
            trial_id="trial-rejected",
        )

    assert len(runtime_supervisor.releases) == 1
    workspace_path = Path(str(runtime_supervisor.launches[0]["workspace_host_path"]))
    assert not workspace_path.exists()


def test_runtime_teardown_failure_preserves_workspace_for_retry(
    tmp_path: Path, monkeypatch
) -> None:
    provider, runtime_supervisor, _ = _provider(tmp_path)
    targets: list[FakeTarget] = []
    _install_fake_target(monkeypatch, provider.declared_target.identity, targets)
    lease = provider.acquire(
        expected_identity=provider.declared_target.identity,
        trial_id="trial-retry",
    )
    workspace_path = Path(str(runtime_supervisor.launches[0]["workspace_host_path"]))
    runtime_supervisor.fail_release = True

    first = asyncio.run(provider.release_async(lease))
    assert first.cleanup_complete is False
    assert workspace_path.exists()

    runtime_supervisor.fail_release = False
    second = asyncio.run(provider.release_async(lease))
    assert second.cleanup_complete is True
    assert not workspace_path.exists()
