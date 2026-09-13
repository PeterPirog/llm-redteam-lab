from types import SimpleNamespace

import pytest

from llm_redteam.disposable_agent_trial_lease import (
    DisposableAgentTargetHandle,
    DisposableAgentTargetRelease,
    DisposableAgentTrialLeaseProvider,
    DisposableAgentWorkspaceLease,
    DisposableAgentWorkspaceRelease,
)
from llm_redteam.domain import TargetClass, TargetIdentity, TargetMode
from llm_redteam.opencode_health import OpenCodeHealthObservation
from llm_redteam.target_trial_isolation import (
    TargetIsolationLevel,
    TargetTrialLeaseProvider,
    validate_target_trial_lease,
)
from llm_redteam.targets.base import SessionMode, TargetRequest, TargetResponse


def _h(char: str) -> str:
    return char * 64


def _identity(*, config: str = "agent-config-v1") -> TargetIdentity:
    return TargetIdentity(
        id="qualified-opencode-agent",
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        model="blue-agent-model",
        provider="ollama",
        runtime="opencode-docker",
        application="opencode",
        application_version="1.2.3",
        configuration_hash=config,
        capabilities=frozenset(
            {
                "text",
                "tools",
                "runtime_health_verified",
            }
        ),
    )


class _Target:
    def __init__(self, identity: TargetIdentity) -> None:
        self._identity = identity

    @property
    def identity(self) -> TargetIdentity:
        return self._identity

    async def execute(self, request: TargetRequest) -> TargetResponse:
        return TargetResponse(text=f"synthetic:{request.attack_id}")


class _WorkspaceProvider:
    provider_fingerprint = _h("1")

    def __init__(self, events: list[str], *, fail_release: bool = False) -> None:
        self.events = events
        self.fail_release = fail_release
        self.counter = 0

    def acquire(self, *, trial_id: str) -> DisposableAgentWorkspaceLease:
        self.events.append("workspace.acquire")
        self.counter += 1
        return DisposableAgentWorkspaceLease(
            host_path=f"C:/synthetic/workspace-{self.counter}",
            workspace_id_sha256=_h("2"),
            fresh_state_proof_sha256=_h("3" if self.counter == 1 else "4"),
        )

    def release(
        self,
        lease: DisposableAgentWorkspaceLease,
    ) -> DisposableAgentWorkspaceRelease:
        self.events.append("workspace.release")
        if self.fail_release:
            raise RuntimeError("synthetic workspace teardown failure")
        return DisposableAgentWorkspaceRelease(
            workspace_id_sha256=lease.workspace_id_sha256,
            teardown_proof_sha256=_h("5"),
            cleanup_complete=True,
        )


class _NetworkSupervisor:
    def __init__(self, events: list[str], *, fail_release: bool = False) -> None:
        self.events = events
        self.fail_release = fail_release
        self.created_names: list[str] = []

    def create(self, *, profile: object, network_name: str):
        self.events.append("network.create")
        self.created_names.append(network_name)
        return SimpleNamespace(
            network_name=network_name,
            network_id_sha256=_h("6"),
            network_profile_sha256=profile.profile_sha256,
            create_command_sha256=_h("7"),
        )

    def release(self, lease: object) -> None:
        self.events.append("network.release")
        if self.fail_release:
            raise RuntimeError("synthetic network teardown failure")


class _ModelPeerSupervisor:
    def __init__(
        self,
        events: list[str],
        *,
        fail_launch: bool = False,
        fail_release: bool = False,
        artifact_stable: bool = True,
    ) -> None:
        self.events = events
        self.fail_launch = fail_launch
        self.fail_release = fail_release
        self.artifact_stable = artifact_stable

    def launch(self, **kwargs):
        self.events.append("model.launch")
        if self.fail_launch:
            raise RuntimeError("synthetic model launch failure")
        network_lease = kwargs["network_lease"]
        return SimpleNamespace(
            container_name="model-peer",
            container_id_sha256=_h("8"),
            profile_sha256=kwargs["profile"].profile_sha256,
            network_id_sha256=network_lease.network_id_sha256,
            launch_command_sha256=_h("9"),
            bundle_contract_sha256=kwargs["bundle_contract"].bundle_sha256,
            prelaunch_bundle_proof_sha256=_h("a"),
        )

    def release(self, **kwargs):
        self.events.append("model.release")
        if self.fail_release:
            raise RuntimeError("synthetic model teardown failure")
        return SimpleNamespace(
            cleanup_complete=True,
            artifact_contract_matched=True,
            artifact_stable=self.artifact_stable,
            proof_sha256=_h("b"),
        )


class _AgentSupervisor:
    def __init__(
        self,
        events: list[str],
        *,
        fail_launch: bool = False,
        fail_release: bool = False,
    ) -> None:
        self.events = events
        self.fail_launch = fail_launch
        self.fail_release = fail_release
        self.container_names: list[str] = []

    def launch(self, **kwargs):
        self.events.append("agent.launch")
        self.container_names.append(kwargs["container_name"])
        if self.fail_launch:
            raise RuntimeError("synthetic agent launch failure")
        return SimpleNamespace(
            container_name=kwargs["container_name"],
            container_id_sha256=_h("c"),
            launch_command_sha256=_h("d"),
            network_id_sha256=kwargs["network_lease"].network_id_sha256,
            sandbox_attestation=SimpleNamespace(attestation_sha256=_h("e")),
            network_attestation=SimpleNamespace(attestation_sha256=_h("f")),
        )

    def release(self, lease: object) -> None:
        self.events.append("agent.release")
        if self.fail_release:
            raise RuntimeError("synthetic agent teardown failure")


class _TargetFactory:
    provider_fingerprint = _h("0")

    def __init__(
        self,
        events: list[str],
        *,
        runtime_profile_sha256: str,
        identity_override: TargetIdentity | None = None,
        healthy: bool = True,
        container_id_sha256: str | None = None,
        sandbox_attestation_sha256: str | None = None,
        fail_release: bool = False,
    ) -> None:
        self.events = events
        self.runtime_profile_sha256 = runtime_profile_sha256
        self.identity_override = identity_override
        self.healthy = healthy
        self.container_id_sha256 = container_id_sha256
        self.sandbox_attestation_sha256 = sandbox_attestation_sha256
        self.fail_release = fail_release

    def build(self, *, agent_lease: object, expected_identity: TargetIdentity):
        self.events.append("target.build")
        identity = self.identity_override or expected_identity
        health = OpenCodeHealthObservation(
            healthy=self.healthy,
            application_version="1.2.3",
            runtime_profile_sha256=self.runtime_profile_sha256,
            sandbox_attestation_sha256=(
                self.sandbox_attestation_sha256
                or agent_lease.sandbox_attestation.attestation_sha256
            ),
            container_id_sha256=(
                self.container_id_sha256 or agent_lease.container_id_sha256
            ),
            endpoint_sha256=_h("a"),
            response_sha256=_h("b"),
        )
        return DisposableAgentTargetHandle(target=_Target(identity), health=health)

    def release(self, handle: DisposableAgentTargetHandle) -> DisposableAgentTargetRelease:
        self.events.append("target.release")
        if self.fail_release:
            raise RuntimeError("synthetic target teardown failure")
        return DisposableAgentTargetRelease(
            teardown_proof_sha256=_h("c"),
            cleanup_complete=True,
        )


def _provider(
    events: list[str],
    *,
    workspace: _WorkspaceProvider | None = None,
    network: _NetworkSupervisor | None = None,
    model: _ModelPeerSupervisor | None = None,
    agent: _AgentSupervisor | None = None,
    target_factory: _TargetFactory | None = None,
) -> tuple[
    DisposableAgentTrialLeaseProvider,
    _WorkspaceProvider,
    _NetworkSupervisor,
    _ModelPeerSupervisor,
    _AgentSupervisor,
    _TargetFactory,
]:
    network_profile = SimpleNamespace(profile_sha256=_h("1"))
    model_peer_profile = SimpleNamespace(profile_sha256=_h("2"))
    ollama_profile = SimpleNamespace(
        profile_sha256=_h("3"),
        peer_profile_sha256=model_peer_profile.profile_sha256,
        bundle_contract_sha256=_h("4"),
    )
    bundle_contract = SimpleNamespace(bundle_sha256=_h("4"))
    agent_profile = SimpleNamespace(
        profile_sha256=_h("5"),
        model_network_profile_sha256=network_profile.profile_sha256,
    )
    runtime_profile = SimpleNamespace(profile_sha256=_h("6"))
    sandbox_policy = SimpleNamespace(
        enforcement_profile_sha256=agent_profile.profile_sha256,
        policy_sha256=_h("7"),
    )
    workspace = workspace or _WorkspaceProvider(events)
    network = network or _NetworkSupervisor(events)
    model = model or _ModelPeerSupervisor(events)
    agent = agent or _AgentSupervisor(events)
    target_factory = target_factory or _TargetFactory(
        events,
        runtime_profile_sha256=runtime_profile.profile_sha256,
    )
    provider = DisposableAgentTrialLeaseProvider(
        workspace_provider=workspace,
        network_supervisor=network,
        network_profile=network_profile,
        model_peer_supervisor=model,
        ollama_profile=ollama_profile,
        model_peer_profile=model_peer_profile,
        bundle_contract=bundle_contract,
        bundle_host_path=__import__("pathlib").Path("C:/synthetic/ollama-bundle"),
        agent_supervisor=agent,
        agent_profile=agent_profile,
        runtime_profile=runtime_profile,
        sandbox_policy=sandbox_policy,
        agent_command=("opencode", "serve"),
        target_factory=target_factory,
    )
    return provider, workspace, network, model, agent, target_factory


def test_provider_attests_disposable_sandbox_and_exact_acquisition_order() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)
    identity = _identity()

    lease = provider.acquire(expected_identity=identity, trial_id="trial-A")

    assert isinstance(provider, TargetTrialLeaseProvider)
    assert provider.isolation_level == TargetIsolationLevel.DISPOSABLE_SANDBOX
    assert lease.attestation.isolation_level == TargetIsolationLevel.DISPOSABLE_SANDBOX
    assert lease.attestation.control_plane_independent is True
    assert lease.attestation.target_configuration_hash == identity.configuration_hash
    validate_target_trial_lease(
        lease,
        expected_identity=identity,
        session_mode=SessionMode.REPLAY,
    )
    assert events == [
        "workspace.acquire",
        "network.create",
        "model.launch",
        "agent.launch",
        "target.build",
    ]


def test_resource_names_are_hash_only_and_fresh_proof_changes_between_trials() -> None:
    events: list[str] = []
    provider, _, network, _, agent, _ = _provider(events)
    identity = _identity()
    raw_trial = "SENSITIVE-TRIAL-TEXT-DO-NOT-LEAK"

    first = provider.acquire(expected_identity=identity, trial_id=raw_trial)
    first_proof = first.attestation.fresh_state_proof_hash
    first_network = network.created_names[-1]
    first_agent = agent.container_names[-1]
    provider.release(first)
    second = provider.acquire(expected_identity=identity, trial_id="another-trial")

    assert raw_trial not in first_network
    assert raw_trial not in first_agent
    assert first_network.startswith("llmrt-net-")
    assert first_agent.startswith("llmrt-agent-")
    assert first.attestation.lease_id_hash != second.attestation.lease_id_hash
    assert first_proof != second.attestation.fresh_state_proof_hash


def test_second_concurrent_lease_is_blocked_before_allocating_resources() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)
    identity = _identity()
    provider.acquire(expected_identity=identity, trial_id="trial-1")
    count = len(events)

    with pytest.raises(RuntimeError, match="concurrent"):
        provider.acquire(expected_identity=identity, trial_id="trial-2")

    assert len(events) == count


def test_target_identity_mismatch_rolls_back_every_acquired_layer_in_reverse_order() -> None:
    events: list[str] = []
    mismatched = _identity(config="different-blue-config")
    runtime_hash = _h("6")
    target_factory = _TargetFactory(
        events,
        runtime_profile_sha256=runtime_hash,
        identity_override=mismatched,
    )
    provider, _, _, _, _, _ = _provider(events, target_factory=target_factory)

    with pytest.raises(ValueError, match="target identity"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-mismatch")

    assert events == [
        "workspace.acquire",
        "network.create",
        "model.launch",
        "agent.launch",
        "target.build",
        "target.release",
        "agent.release",
        "model.release",
        "network.release",
        "workspace.release",
    ]


def test_agent_launch_failure_rolls_back_only_previously_acquired_layers() -> None:
    events: list[str] = []
    agent = _AgentSupervisor(events, fail_launch=True)
    provider, _, _, _, _, _ = _provider(events, agent=agent)

    with pytest.raises(RuntimeError, match="synthetic agent launch failure"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-agent-fail")

    assert events == [
        "workspace.acquire",
        "network.create",
        "model.launch",
        "agent.launch",
        "model.release",
        "network.release",
        "workspace.release",
    ]


def test_unhealthy_health_gate_rolls_back_before_returning_public_lease() -> None:
    events: list[str] = []
    target_factory = _TargetFactory(
        events,
        runtime_profile_sha256=_h("6"),
        healthy=False,
    )
    provider, _, _, _, _, _ = _provider(events, target_factory=target_factory)

    with pytest.raises(ValueError, match="unhealthy"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-unhealthy")

    assert events[-5:] == [
        "target.release",
        "agent.release",
        "model.release",
        "network.release",
        "workspace.release",
    ]


def test_normal_release_is_reverse_order_and_cannot_be_repeated() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-release")
    events.clear()

    release = provider.release(lease)

    assert release.cleanup_complete is True
    assert release.lease_id_hash == lease.attestation.lease_id_hash
    assert events == [
        "target.release",
        "agent.release",
        "model.release",
        "network.release",
        "workspace.release",
    ]
    with pytest.raises(ValueError, match="already released"):
        provider.release(lease)


def test_release_attempts_all_layers_even_when_one_cleanup_fails_and_then_blocks_reuse() -> None:
    events: list[str] = []
    agent = _AgentSupervisor(events, fail_release=True)
    provider, _, _, _, _, _ = _provider(events, agent=agent)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-cleanup-fail")
    events.clear()

    with pytest.raises(RuntimeError, match="release failed closed"):
        provider.release(lease)

    assert events == [
        "target.release",
        "agent.release",
        "model.release",
        "network.release",
        "workspace.release",
    ]
    with pytest.raises(RuntimeError, match="dirty"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-after-dirty")


def test_model_artifact_drift_after_cleanup_fails_closed() -> None:
    events: list[str] = []
    model = _ModelPeerSupervisor(events, artifact_stable=False)
    provider, _, _, _, _, _ = _provider(events, model=model)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-drift")
    events.clear()

    with pytest.raises(RuntimeError, match="artifact drift"):
        provider.release(lease)

    assert events == [
        "target.release",
        "agent.release",
        "model.release",
        "network.release",
        "workspace.release",
    ]
