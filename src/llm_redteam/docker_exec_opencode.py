"""Bind the ownership-checked Docker-exec HTTP transport to OpenCode target identity.

The normal ``OpenCodeTarget`` remains unchanged for host-reachable deployments.  This
specialization is for an OpenCode server bound to loopback inside an owned container:
Basic-auth material is resolved inside the container by ``DockerExecHttpTransport`` and
the stable transport policy becomes part of the logical Blue target configuration.
Per-run container identity is evidence only and never changes the logical target.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from .agent_actions import canonical_json_hash
from .docker_exec_http import DockerExecContainerRef, DockerExecHttpTransport
from .docker_supervisor import DockerCommandRunner
from .opencode_runtime import (
    AttestedOpenCodeTarget,
    OpenCodeLaunchPlan,
    OpenCodeRuntimeProfile,
)
from .targets.base import TargetRequest, TargetResponse
from .targets.opencode import OpenCodeConfig, OpenCodeTarget


class DockerExecOpenCodeTarget(OpenCodeTarget):
    """OpenCode target whose control HTTP is tunneled through its owned container."""

    def __init__(
        self,
        config: OpenCodeConfig,
        *,
        runtime_profile: OpenCodeRuntimeProfile,
        container: DockerExecContainerRef,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        _validate_transport_binding(config=config, runtime_profile=runtime_profile)
        transport = DockerExecHttpTransport(
            runtime_profile=runtime_profile,
            container=container,
            username=config.username,
            runner=runner,
            command_timeout_seconds=max(config.timeout_seconds + 15.0, 30.0),
        )
        client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            transport=transport,
        )
        super().__init__(config, client=client)
        self.runtime_profile = runtime_profile
        self.container = container
        self.transport = transport
        self._docker_exec_client = client

    @property
    def identity(self):
        base = super().identity
        return base.model_copy(
            update={
                "configuration_hash": canonical_json_hash(
                    {
                        "base_target_configuration_hash": base.configuration_hash,
                        "control_transport_profile_sha256": (
                            self.transport.profile.profile_sha256
                        ),
                    }
                ),
                "capabilities": base.capabilities
                | frozenset({"docker_exec_control_transport"}),
            }
        )

    def _auth(self):
        """Transport reconstructs Basic auth from the container-local secret env."""

        return None

    async def execute(self, request: TargetRequest) -> TargetResponse:
        response = await super().execute(request)
        metadata = dict(response.provider_metadata)
        metadata.update(
            {
                "control_transport": self.transport.profile.transport_kind,
                "control_transport_profile_sha256": (
                    self.transport.profile.profile_sha256
                ),
                "control_transport_container_id_sha256": (
                    self.container.container_id_sha256
                ),
            }
        )
        return response.model_copy(update={"provider_metadata": metadata})

    async def aclose(self) -> None:
        await self._docker_exec_client.aclose()


def build_attested_docker_exec_opencode_target(
    *,
    config: OpenCodeConfig,
    runtime_profile: OpenCodeRuntimeProfile,
    launch_plan: OpenCodeLaunchPlan,
    container: DockerExecContainerRef,
    runner: DockerCommandRunner | None = None,
) -> AttestedOpenCodeTarget:
    """Construct the networked target and bind it to the existing launch attestation."""

    target = DockerExecOpenCodeTarget(
        config,
        runtime_profile=runtime_profile,
        container=container,
        runner=runner,
    )
    return AttestedOpenCodeTarget(target, launch_plan)


def _validate_transport_binding(
    *,
    config: OpenCodeConfig,
    runtime_profile: OpenCodeRuntimeProfile,
) -> None:
    parsed = urlparse(config.base_url)
    if parsed.scheme != "http" or parsed.hostname is None:
        raise ValueError("Docker-exec OpenCode target requires an HTTP loopback base_url")
    configured_port = parsed.port or 80
    if parsed.hostname.casefold() != runtime_profile.hostname.casefold():
        raise ValueError("OpenCode target host does not match Docker-exec runtime profile")
    if configured_port != runtime_profile.port:
        raise ValueError("OpenCode target port does not match Docker-exec runtime profile")
    if config.password_env != runtime_profile.server_password_env:
        raise ValueError(
            "OpenCode target password_env does not match Docker-exec runtime profile"
        )
