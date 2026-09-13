from pathlib import Path
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


def _counter_hash(value: int) -> str:
    return f"{value:064x}"


def _identity(
    *,
    config: str = "agent-config-v1",
    application_version: str | None = "1.2.3",
) -> TargetIdentity:
    return TargetIdentity(
        id="qualified-opencode-agent",
        target_class=TargetClass.CODING,
        target_mode=TargetMode.AGENT,
        model="blue-agent-model",
        provider="ollama",
        runtime="opencode-docker",
        application="opencode",
        application_version=application_version,
        configuration_hash=config,
        capabilities=frozenset({"text", "tools", "runtime_health_verified"}),
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

    def __init__(
        self,
        events: list[str],
        *,
        fail_release: bool = False,
        reuse_workspace: bool = False,
        reuse_fresh_proof: bool = False,
    ) -> None:
        self.events = events
        self.fail_release = fail_release
        self.reuse_workspace = reuse_workspace
        self.reuse_fresh_proof = reuse_fresh_proof
        self.counter = 0

    def acquire(self, *, trial_id: str) -> DisposableAgentWorkspaceLease:
        self.events.append("workspace.acquire")
        self.counter += 1
        workspace_number = 1 if self.reuse_workspace else self.counter
        proof_number = 100 if self.reuse_fresh_proof else 100 + self.counter
        return DisposableAgentWorkspaceLease(
            host_path=f"C:/synthetic/workspace-{self.counter}",
            workspace_id_sha256=_counter_hash(workspace_number),
            fresh_state_proof_sha256=_counter_hash(proof_number),
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
    def __init__(
        self,
        events: list[str],
        *,
        runtime_profile_sha256: str,
        identity_override: TargetIdentity | None = None,
        healthy: bool = True,
        application_version: str = "1.2.3",
        container_id_sha256: str | None = None,
        sandbox_attestation_sha256: str | None = None,
        fail_release: bool = False,
        fingerprint_char: str = "0",
    ) -> None:
        self.events = events
        self.runtime_profile_sha256 = runtime_profile_sha256
        self.identity_override = identity_override
        self.healthy = healthy
        self.application_version = application_version
        self.container_id_sha256 = container_id_sha256
        self.sandbox_attestation_sha256 = sandbox_attestation_sha256
        self.fail_release = fail_release
        self.provider_fingerprint = _h(fingerprint_char)

    def build(self, *, agent_lease: object, expected_identity: TargetIdentity):
        self.events.append("target.build")
        identity = self.identity_override or expected_identity
        health = OpenCodeHealthObservation(
            healthy=self.healthy,
            application_version=self.application_version,
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
        bundle_host_path=Path("C:/synthetic/ollama-bundle"),
        agent_supervisor=agent,
        agent_profile=agent_profile,
        runtime_profile=runtime_profile,
        sandbox_policy=sandbox_policy,
        agent_command=("opencode", "serve"),
        target_factory=target_factory,
    )
    return provider, workspace, network, model, agent, target_factory


def _all_acquire_events() -> list[str]:
    return [
        "workspace.acquire",
        "network.create",
        "model.launch",
        "agent.launch",
        "target.build",
    ]


def _all_release_events() -> list[str]:
    return [
        "target.release",
        "agent.release",
        "model.release",
        "network.release",
        "workspace.release",
    ]


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
    assert events == _all_acquire_events()


def test_provider_fingerprint_is_stable_and_changes_with_trusted_factory_policy() -> None:
    first_events: list[str] = []
    second_events: list[str] = []
    changed_events: list[str] = []
    first, _, _, _, _, _ = _provider(first_events)
    second, _, _, _, _, _ = _provider(second_events)
    changed_factory = _TargetFactory(
        changed_events,
        runtime_profile_sha256=_h("6"),
        fingerprint_char="9",
    )
    changed, _, _, _, _, _ = _provider(
        changed_events,
        target_factory=changed_factory,
    )

    assert first.provider_fingerprint == second.provider_fingerprint
    assert first.provider_fingerprint != changed.provider_fingerprint


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


def test_same_trial_lease_identity_cannot_be_reused_after_release() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)
    identity = _identity()
    first = provider.acquire(expected_identity=identity, trial_id="trial-reuse")
    provider.release(first)
    events.clear()

    with pytest.raises(ValueError, match="lease identity was already used"):
        provider.acquire(expected_identity=identity, trial_id="trial-reuse")

    assert events == []


def test_workspace_identity_reuse_is_rejected_and_only_workspace_is_rolled_back() -> None:
    events: list[str] = []
    workspace = _WorkspaceProvider(events, reuse_workspace=True)
    provider, _, _, _, _, _ = _provider(events, workspace=workspace)
    identity = _identity()
    first = provider.acquire(expected_identity=identity, trial_id="trial-workspace-1")
    provider.release(first)
    events.clear()

    with pytest.raises(RuntimeError, match="workspace identity was reused"):
        provider.acquire(expected_identity=identity, trial_id="trial-workspace-2")

    assert events == ["workspace.acquire", "workspace.release"]


def test_workspace_fresh_proof_reuse_is_rejected() -> None:
    events: list[str] = []
    workspace = _WorkspaceProvider(events, reuse_fresh_proof=True)
    provider, _, _, _, _, _ = _provider(events, workspace=workspace)
    identity = _identity()
    first = provider.acquire(expected_identity=identity, trial_id="trial-proof-1")
    provider.release(first)
    events.clear()

    with pytest.raises(RuntimeError, match="fresh-state proof was reused"):
        provider.acquire(expected_identity=identity, trial_id="trial-proof-2")

    assert events == ["workspace.acquire", "workspace.release"]


def test_target_identity_mismatch_rolls_back_every_layer_in_reverse_order() -> None:
    events: list[str] = []
    target_factory = _TargetFactory(
        events,
        runtime_profile_sha256=_h("6"),
        identity_override=_identity(config="different-blue-config"),
    )
    provider, _, _, _, _, _ = _provider(events, target_factory=target_factory)

    with pytest.raises(ValueError, match="target identity"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-mismatch")

    assert events == _all_acquire_events() + _all_release_events()


def test_model_launch_failure_rolls_back_workspace_and_network_only() -> None:
    events: list[str] = []
    model = _ModelPeerSupervisor(events, fail_launch=True)
    provider, _, _, _, _, _ = _provider(events, model=model)

    with pytest.raises(RuntimeError, match="synthetic model launch failure"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-model-fail")

    assert events == [
        "workspace.acquire",
        "network.create",
        "model.launch",
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


@pytest.mark.parametrize(
    ("factory_kwargs", "message"),
    [
        ({"healthy": False}, "unhealthy"),
        ({"container_id_sha256": _h("1")}, "launched AGENT container"),
        ({"sandbox_attestation_sha256": _h("1")}, "sandbox attestation"),
        ({"runtime_profile_sha256": _h("1")}, "runtime profile"),
        ({"application_version": "9.9.9"}, "expected target version"),
    ],
)
def test_health_binding_failures_roll_back_before_public_lease(
    factory_kwargs: dict[str, object],
    message: str,
) -> None:
    events: list[str] = []
    runtime_hash = str(factory_kwargs.pop("runtime_profile_sha256", _h("6")))
    target_factory = _TargetFactory(
        events,
        runtime_profile_sha256=runtime_hash,
        **factory_kwargs,
    )
    provider, _, _, _, _, _ = _provider(events, target_factory=target_factory)

    with pytest.raises(ValueError, match=message):
        provider.acquire(expected_identity=_identity(), trial_id=f"trial-{message}")

    assert events == _all_acquire_events() + _all_release_events()


def test_missing_expected_application_version_is_rejected_and_rolled_back() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)

    with pytest.raises(ValueError, match="requires application_version"):
        provider.acquire(
            expected_identity=_identity(application_version=None),
            trial_id="trial-no-version",
        )

    assert events == _all_acquire_events() + _all_release_events()


def test_normal_release_is_reverse_order_and_cannot_be_repeated() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-release")
    events.clear()

    release = provider.release(lease)

    assert release.cleanup_complete is True
    assert release.lease_id_hash == lease.attestation.lease_id_hash
    assert events == _all_release_events()
    with pytest.raises(ValueError, match="already released"):
        provider.release(lease)


def test_target_identity_drift_at_release_still_cleans_every_layer_and_marks_dirty() -> None:
    events: list[str] = []
    provider, _, _, _, _, _ = _provider(events)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-target-drift")
    setattr(lease.target, "_identity", _identity(config="drifted-after-admission"))
    events.clear()

    with pytest.raises(RuntimeError, match="target identity drift"):
        provider.release(lease)

    assert events == _all_release_events()
    with pytest.raises(RuntimeError, match="dirty"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-after-target-drift")


def test_release_attempts_all_layers_even_when_cleanup_fails_and_blocks_reuse() -> None:
    events: list[str] = []
    agent = _AgentSupervisor(events, fail_release=True)
    provider, _, _, _, _, _ = _provider(events, agent=agent)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-cleanup-fail")
    events.clear()

    with pytest.raises(RuntimeError, match="release failed closed"):
        provider.release(lease)

    assert events == _all_release_events()
    with pytest.raises(RuntimeError, match="dirty"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-after-dirty")


def test_acquisition_rollback_failure_marks_provider_dirty() -> None:
    events: list[str] = []
    workspace = _WorkspaceProvider(events, fail_release=True)
    agent = _AgentSupervisor(events, fail_launch=True)
    provider, _, _, _, _, _ = _provider(events, workspace=workspace, agent=agent)

    with pytest.raises(RuntimeError, match="rollback was incomplete"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-rollback-fail")

    assert events == [
        "workspace.acquire",
        "network.create",
        "model.launch",
        "agent.launch",
        "model.release",
        "network.release",
        "workspace.release",
    ]
    with pytest.raises(RuntimeError, match="dirty"):
        provider.acquire(expected_identity=_identity(), trial_id="trial-after-rollback-fail")


def test_model_artifact_drift_after_cleanup_fails_closed() -> None:
    events: list[str] = []
    model = _ModelPeerSupervisor(events, artifact_stable=False)
    provider, _, _, _, _, _ = _provider(events, model=model)
    lease = provider.acquire(expected_identity=_identity(), trial_id="trial-drift")
    events.clear()

    with pytest.raises(RuntimeError, match="artifact drift"):
        provider.release(lease)

    assert events == _all_release_events()
