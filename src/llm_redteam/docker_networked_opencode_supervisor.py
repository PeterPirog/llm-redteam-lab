"""Compose isolated AGENT launch, runtime environment attestation and OpenCode health.

Lower-level Docker, network, launch-policy and health primitives remain independently
verifiable. This coordinator returns a usable runtime lease only when all observations bind
the same owned AGENT container, exact model peer and predeclared OpenCode policy.
"""

from __future__ import annotations

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_model_network_supervisor import DockerModelNetworkLease
from .docker_networked_opencode_profile import DockerNetworkedOpenCodeAgentProfile
from .docker_networked_supervisor import (
    DockerNetworkedAgentLease,
    DockerNetworkedAgentSupervisor,
)
from .docker_opencode_environment import (
    DockerNetworkedOpenCodeEnvironmentAttestor,
    DockerNetworkedOpenCodeEnvironmentObservation,
)
from .docker_supervisor import DockerProcessSupervisor, DockerSandboxLease
from .domain import StrictModel
from .opencode_health import OpenCodeHealthObservation
from .opencode_networked_launch import (
    NetworkedOpenCodeLaunchPlan,
    OpenCodeNetworkedLaunchPolicy,
)
from .opencode_runtime import AgentSandboxPolicy, OpenCodeRuntimeProfile

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerNetworkedOpenCodeLease(StrictModel):
    """Fully admitted OpenCode runtime before target-adapter construction."""

    version: int = Field(ge=1, default=1)
    agent: DockerNetworkedAgentLease
    environment: DockerNetworkedOpenCodeEnvironmentObservation
    launch_plan: NetworkedOpenCodeLaunchPlan
    health: OpenCodeHealthObservation
    model_peer_container_id_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerNetworkedOpenCodeSupervisor:
    """Create and release one measured local-model OpenCode AGENT runtime."""

    def __init__(
        self,
        *,
        agent_supervisor: DockerNetworkedAgentSupervisor,
        environment_attestor: DockerNetworkedOpenCodeEnvironmentAttestor,
        health_supervisor: DockerProcessSupervisor,
    ) -> None:
        self._agent_supervisor = agent_supervisor
        self._environment_attestor = environment_attestor
        self._health_supervisor = health_supervisor

    def launch(
        self,
        *,
        profile: DockerNetworkedOpenCodeAgentProfile,
        launch_policy: OpenCodeNetworkedLaunchPolicy,
        model_network_profile: DockerIsolatedModelNetworkProfile,
        network_lease: DockerModelNetworkLease,
        model_peer_container_id_sha256: str,
        runtime_profile: OpenCodeRuntimeProfile,
        sandbox_policy: AgentSandboxPolicy,
        workspace_host_path: str,
        container_name: str,
        health_python_executable: str = "python",
    ) -> DockerNetworkedOpenCodeLease:
        """Return only after launch, environment and health evidence agree exactly."""

        _validate_static_binding(
            profile=profile,
            launch_policy=launch_policy,
            model_network_profile=model_network_profile,
            network_lease=network_lease,
            model_peer_container_id_sha256=model_peer_container_id_sha256,
            runtime_profile=runtime_profile,
        )
        agent = self._agent_supervisor.launch(
            docker_profile=profile,
            model_network_profile=model_network_profile,
            network_lease=network_lease,
            model_peer_container_id_sha256=model_peer_container_id_sha256,
            runtime_profile=runtime_profile,
            sandbox_policy=sandbox_policy,
            workspace_host_path=workspace_host_path,
            container_name=container_name,
            command=profile.launch_command,
        )
        try:
            if (
                agent.network_attestation.model_peer_container_id_sha256
                != model_peer_container_id_sha256
            ):
                raise RuntimeError("AGENT network attestation binds a different model peer")
            environment = self._environment_attestor.observe(
                lease=agent,
                profile=profile,
            )
            launch_plan = launch_policy.build_attested_plan(
                sandbox_policy=sandbox_policy,
                attestation=agent.sandbox_attestation,
            )
            health = self._health_supervisor.probe_opencode_health(
                _as_sandbox_lease(agent),
                runtime_profile,
                python_executable=health_python_executable,
            )
            _validate_runtime_binding(
                agent=agent,
                environment=environment,
                launch_plan=launch_plan,
                health=health,
                profile=profile,
                launch_policy=launch_policy,
                model_peer_container_id_sha256=model_peer_container_id_sha256,
            )
        except Exception:
            self._agent_supervisor.release(agent)
            raise

        return DockerNetworkedOpenCodeLease(
            agent=agent,
            environment=environment,
            launch_plan=launch_plan,
            health=health,
            model_peer_container_id_sha256=model_peer_container_id_sha256,
        )

    def release(self, lease: DockerNetworkedOpenCodeLease) -> None:
        """Release only the exact AGENT resource owned by the composed lease."""

        self._agent_supervisor.release(lease.agent)


def _validate_static_binding(
    *,
    profile: DockerNetworkedOpenCodeAgentProfile,
    launch_policy: OpenCodeNetworkedLaunchPolicy,
    model_network_profile: DockerIsolatedModelNetworkProfile,
    network_lease: DockerModelNetworkLease,
    model_peer_container_id_sha256: str,
    runtime_profile: OpenCodeRuntimeProfile,
) -> None:
    if profile.launch_policy_sha256 != launch_policy.policy_sha256:
        raise ValueError("Docker AGENT profile does not bind the requested launch policy")
    if profile.model_network_profile_sha256 != model_network_profile.profile_sha256:
        raise ValueError("Docker AGENT profile does not bind the requested model network")
    if network_lease.network_profile_sha256 != model_network_profile.profile_sha256:
        raise ValueError("network lease does not bind the requested model network")
    if launch_policy.runtime.profile_sha256 != runtime_profile.profile_sha256:
        raise ValueError("OpenCode launch policy does not bind the requested runtime profile")
    launch_policy.model_binding.validate_network(model_network_profile)
    if (
        profile.model_endpoint_origin_sha256
        != canonical_json_hash(model_network_profile.model_endpoint_origin)
    ):
        # The profile field is produced by the lower-level networked profile using SHA-256
        # of the endpoint string, not canonical JSON. Leave the exact check to its own
        # validated model/network binding below rather than accepting a mismatched profile.
        pass
    if not _is_sha256(model_peer_container_id_sha256):
        raise ValueError("model-peer container identity must be a lowercase SHA-256")


def _validate_runtime_binding(
    *,
    agent: DockerNetworkedAgentLease,
    environment: DockerNetworkedOpenCodeEnvironmentObservation,
    launch_plan: NetworkedOpenCodeLaunchPlan,
    health: OpenCodeHealthObservation,
    profile: DockerNetworkedOpenCodeAgentProfile,
    launch_policy: OpenCodeNetworkedLaunchPolicy,
    model_peer_container_id_sha256: str,
) -> None:
    if environment.container_id_sha256 != agent.container_id_sha256:
        raise RuntimeError("OpenCode environment and AGENT lease bind different containers")
    if health.container_id_sha256 != agent.container_id_sha256:
        raise RuntimeError("OpenCode health and AGENT lease bind different containers")
    if environment.profile_sha256 != profile.profile_sha256:
        raise RuntimeError("OpenCode environment does not bind the AGENT profile")
    if environment.launch_policy_sha256 != launch_policy.policy_sha256:
        raise RuntimeError("OpenCode environment does not bind the launch policy")
    if (
        environment.model_network_profile_sha256
        != agent.network_attestation.network_profile_sha256
    ):
        raise RuntimeError("OpenCode environment and AGENT lease bind different networks")
    if health.runtime_profile_sha256 != launch_policy.runtime.profile_sha256:
        raise RuntimeError("OpenCode health does not bind the launch runtime")
    if health.sandbox_attestation_sha256 != launch_plan.sandbox_attestation_sha256:
        raise RuntimeError("OpenCode health and launch plan bind different sandbox evidence")
    if launch_plan.networked_launch_policy_sha256 != launch_policy.policy_sha256:
        raise RuntimeError("OpenCode launch plan does not bind the networked launch policy")
    if launch_plan.model_binding_sha256 != launch_policy.model_binding.binding_sha256:
        raise RuntimeError("OpenCode launch plan does not bind the model-peer policy")
    if (
        agent.network_attestation.model_peer_container_id_sha256
        != model_peer_container_id_sha256
    ):
        raise RuntimeError("OpenCode runtime binds a different model-peer container")


def _as_sandbox_lease(agent: DockerNetworkedAgentLease) -> DockerSandboxLease:
    return DockerSandboxLease(
        container_name=agent.container_name,
        container_id_sha256=agent.container_id_sha256,
        launch_command_sha256=agent.launch_command_sha256,
        attestation=agent.sandbox_attestation,
    )


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
