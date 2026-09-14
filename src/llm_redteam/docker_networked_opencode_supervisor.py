"""Compose isolated AGENT launch, environment attestation and OpenCode health.

The lower-level supervisors remain independently testable.  This coordinator only returns
a usable OpenCode runtime lease after the networked Docker sandbox, exact application
launch policy, and runtime health have all been proven for the same owned container.
"""

from __future__ import annotations

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
from .opencode_networked_launch import OpenCodeNetworkedLaunchPolicy
from .opencode_runtime import AgentSandboxPolicy, OpenCodeLaunchPlan, OpenCodeRuntimeProfile


class DockerNetworkedOpenCodeLease(StrictModel):
    """One fully admitted networked OpenCode runtime before target construction."""

    agent: DockerNetworkedAgentLease
    environment: DockerNetworkedOpenCodeEnvironmentObservation
    launch_plan: OpenCodeLaunchPlan
    health: OpenCodeHealthObservation


class DockerNetworkedOpenCodeSupervisor:
    """Create and tear down one measured local-model OpenCode AGENT runtime."""

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
        """Return a lease only after all independent launch observations agree."""

        if profile.launch_policy_sha256 != launch_policy.policy_sha256:
            raise ValueError("Docker AGENT profile does not bind the requested launch policy")
        if launch_policy.runtime.profile_sha256 != runtime_profile.profile_sha256:
            raise ValueError("OpenCode launch policy does not bind the requested runtime profile")
        if launch_policy.model_binding.endpoint_origin != model_network_profile.model_endpoint_origin:
            raise ValueError("OpenCode launch policy does not bind the requested model network")

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
        except Exception:
            self._agent_supervisor.release(agent)
            raise

        if environment.container_id_sha256 != health.container_id_sha256:
            self._agent_supervisor.release(agent)
            raise RuntimeError("OpenCode environment and health observations bind different containers")
        if health.sandbox_attestation_sha256 != launch_plan.sandbox_attestation_sha256:
            self._agent_supervisor.release(agent)
            raise RuntimeError("OpenCode health and launch plan bind different sandbox attestations")

        return DockerNetworkedOpenCodeLease(
            agent=agent,
            environment=environment,
            launch_plan=launch_plan,
            health=health,
        )

    def release(self, lease: DockerNetworkedOpenCodeLease) -> None:
        """Release only the exact AGENT resource owned by the composed lease."""

        self._agent_supervisor.release(lease.agent)


def _as_sandbox_lease(agent: DockerNetworkedAgentLease) -> DockerSandboxLease:
    """Adapt shared ownership fields for the existing independent health probe."""

    return DockerSandboxLease(
        container_name=agent.container_name,
        container_id_sha256=agent.container_id_sha256,
        launch_command_sha256=agent.launch_command_sha256,
        attestation=agent.sandbox_attestation,
    )
