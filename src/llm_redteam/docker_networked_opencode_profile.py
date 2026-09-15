"""Hardened Docker AGENT profile carrying an exact networked OpenCode launch policy.

Secret values are never part of the stable profile. Only secret environment-variable
names may be inherited into Docker at execution time.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .docker_networked_sandbox import DockerNetworkedAgentProfile
from .docker_sandbox import DockerSandboxProfile
from .opencode_networked_launch import OpenCodeNetworkedLaunchPolicy

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerNetworkedOpenCodeAgentProfile(DockerNetworkedAgentProfile):
    """Stable Docker profile for one OpenCode AGENT and one exact HAL model peer."""

    launch_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_command: tuple[str, ...] = Field(min_length=1)
    public_environment: dict[str, str]
    required_secret_env_names: tuple[str, ...] = ()

    @model_validator(mode="after")
    def environment_contract_is_safe(self) -> DockerNetworkedOpenCodeAgentProfile:
        for name, value in self.public_environment.items():
            _validate_env_name(name)
            if "\x00" in value:
                raise ValueError("public environment values cannot contain NUL")
        for name in self.required_secret_env_names:
            _validate_env_name(name)
            if name in self.public_environment:
                raise ValueError("secret environment names cannot overlap public environment")
        if len(set(self.required_secret_env_names)) != len(self.required_secret_env_names):
            raise ValueError("secret environment names must be unique")
        return self

    @classmethod
    def compose(
        cls,
        *,
        sandbox: DockerSandboxProfile,
        model_network: DockerIsolatedModelNetworkProfile,
        launch_policy: OpenCodeNetworkedLaunchPolicy,
    ) -> DockerNetworkedOpenCodeAgentProfile:
        launch_policy.model_binding.validate_network(model_network)
        base = DockerNetworkedAgentProfile.compose(
            sandbox=sandbox,
            model_network=model_network,
        )
        return cls(
            **base.model_dump(mode="python"),
            launch_policy_sha256=launch_policy.policy_sha256,
            launch_command=launch_policy.command,
            public_environment=launch_policy.public_environment,
            required_secret_env_names=launch_policy.required_secret_env_names,
        )

    @property
    def profile_sha256(self) -> str:
        base = DockerNetworkedAgentProfile.model_validate(
            {
                "version": self.version,
                "image_ref": self.image_ref,
                "image_id": self.image_id,
                "container_workspace": self.container_workspace,
                "memory_limit_bytes": self.memory_limit_bytes,
                "pids_limit": self.pids_limit,
                "cpus": self.cpus,
                "model_network_profile_sha256": self.model_network_profile_sha256,
                "model_endpoint_origin_sha256": self.model_endpoint_origin_sha256,
            }
        )
        return canonical_json_hash(
            {
                "version": 1,
                "networked_agent_profile_sha256": base.profile_sha256,
                "launch_policy_sha256": self.launch_policy_sha256,
                "launch_command": list(self.launch_command),
                "public_environment": self.public_environment,
                "required_secret_env_names": list(self.required_secret_env_names),
                "environment_transport": "docker-env-by-name-v1",
            }
        )

    def docker_run_command(
        self,
        *,
        container_name: str,
        workspace_host_path: str,
        network_name: str,
        command: tuple[str, ...],
        detach: bool = False,
    ) -> tuple[str, ...]:
        """Build hardened Docker launch args with the exact application environment."""

        if command != self.launch_command:
            raise ValueError("OpenCode command does not match the bound launch policy")
        base = super().docker_run_command(
            container_name=container_name,
            workspace_host_path=workspace_host_path,
            network_name=network_name,
            command=command,
            detach=detach,
        )
        try:
            image_index = base.index(self.image_ref)
        except ValueError as exc:  # pragma: no cover - inherited invariant
            raise RuntimeError("Docker launch command lost its image reference") from exc

        environment_args: list[str] = []
        for name in sorted(self.public_environment):
            environment_args.extend(("--env", f"{name}={self.public_environment[name]}"))
        for name in sorted(self.required_secret_env_names):
            environment_args.extend(("--env", name))
        return (*base[:image_index], *environment_args, *base[image_index:])


def _validate_env_name(value: str) -> None:
    if not value or not (value[0].isalpha() or value[0] == "_"):
        raise ValueError("environment names must be identifier-like")
    if not all(character.isalnum() or character == "_" for character in value):
        raise ValueError("environment names must be identifier-like")
