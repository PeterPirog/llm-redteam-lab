"""Pre-attestation OpenCode process policy for networked Docker AGENT trials.

The historical :class:`OpenCodeLaunchPlan` is intentionally post-attestation: it binds a
runtime process definition to per-run sandbox evidence. A real container, however, must
receive the command and environment before that evidence exists. This module separates
those phases without changing the historical plan or base Docker profiles.
"""

from __future__ import annotations

import re
from hashlib import sha256

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_networked_sandbox import DockerNetworkedAgentProfile
from .domain import StrictModel
from .opencode_runtime import (
    AgentSandboxPolicy,
    OpenCodeLaunchPlan,
    OpenCodeRuntimeProfile,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class OpenCodePrelaunchContract(StrictModel):
    """Stable non-secret process policy required before an OpenCode container starts."""

    version: int = Field(ge=1, default=1)
    cwd: str = Field(min_length=1)
    command: tuple[str, ...] = Field(min_length=1)
    public_environment: dict[str, str]
    required_secret_env_names: tuple[str, ...] = ()
    runtime_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    workspace_root_sha256: str = Field(pattern=_HASH_PATTERN)
    mcp_fixture_bridge_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def environment_contract_is_valid(self) -> OpenCodePrelaunchContract:
        for name in self.public_environment:
            if _ENV_NAME.fullmatch(name) is None:
                raise ValueError("public environment contains an invalid variable name")
        if len(set(self.required_secret_env_names)) != len(
            self.required_secret_env_names
        ):
            raise ValueError("secret environment variable names must be unique")
        for name in self.required_secret_env_names:
            if _ENV_NAME.fullmatch(name) is None:
                raise ValueError("secret environment contains an invalid variable name")
            if name in self.public_environment:
                raise ValueError("public and secret environment variables must be disjoint")
        return self

    @property
    def contract_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerOpenCodeNetworkedAgentProfile(DockerNetworkedAgentProfile):
    """Networked sandbox whose stable identity includes exact OpenCode prelaunch policy."""

    runtime_launch: OpenCodePrelaunchContract

    @classmethod
    def compose(
        cls,
        *,
        sandbox: DockerNetworkedAgentProfile,
        runtime_launch: OpenCodePrelaunchContract,
    ) -> DockerOpenCodeNetworkedAgentProfile:
        return cls(
            **sandbox.model_dump(mode="python"),
            runtime_launch=runtime_launch,
        )

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": 1,
                "base_networked_profile_sha256": super().profile_sha256,
                "runtime_launch_contract_sha256": self.runtime_launch.contract_sha256,
                "launch_semantics": "opencode-prelaunch-environment-v1",
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
        if command != self.runtime_launch.command:
            raise ValueError(
                "Docker OpenCode launch command differs from prelaunch contract"
            )
        base = super().docker_run_command(
            container_name=container_name,
            workspace_host_path=workspace_host_path,
            network_name=network_name,
            command=command,
            detach=detach,
        )
        try:
            image_index = base.index(self.image_ref)
        except ValueError as exc:
            raise RuntimeError(
                "Docker launch command does not contain the declared image"
            ) from exc

        environment_args: list[str] = []
        for name in sorted(self.runtime_launch.public_environment):
            environment_args.extend(
                ("--env", f"{name}={self.runtime_launch.public_environment[name]}")
            )
        for name in sorted(self.runtime_launch.required_secret_env_names):
            # Docker copies the value from the supervisor environment. The secret value
            # itself is deliberately absent from argv and from this stable contract.
            environment_args.extend(("--env", name))
        return (*base[:image_index], *environment_args, *base[image_index:])


class OpenCodeDockerProcessObservation(StrictModel):
    """Hash-only proof that Docker process state matches the prelaunch contract."""

    prelaunch_contract_sha256: str = Field(pattern=_HASH_PATTERN)
    command_sha256: str = Field(pattern=_HASH_PATTERN)
    working_directory_sha256: str = Field(pattern=_HASH_PATTERN)
    public_environment_sha256: str = Field(pattern=_HASH_PATTERN)
    secret_environment_names_sha256: str = Field(pattern=_HASH_PATTERN)
    entrypoint_empty: bool

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class OpenCodeAttestedLaunchBinding(StrictModel):
    """Per-run proof that the attested plan matches what was required before launch."""

    prelaunch_contract_sha256: str = Field(pattern=_HASH_PATTERN)
    sandbox_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_plan_sha256: str = Field(pattern=_HASH_PATTERN)
    target_policy_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


def build_opencode_prelaunch_contract(
    profile: OpenCodeRuntimeProfile,
) -> OpenCodePrelaunchContract:
    """Derive exactly the process settings that must exist before sandbox attestation."""

    environment = {
        "OPENCODE_AUTO_SHARE": "false",
        "OPENCODE_DISABLE_AUTOUPDATE": "true",
        "OPENCODE_CONFIG_CONTENT": profile.config_json(),
    }
    required_secret_env_names = (
        (profile.server_password_env,) if profile.server_password_env is not None else ()
    )
    command = (
        profile.executable,
        "--pure",
        "serve",
        "--hostname",
        profile.hostname,
        "--port",
        str(profile.port),
    )
    return OpenCodePrelaunchContract(
        cwd=profile.workspace_root,
        command=command,
        public_environment=environment,
        required_secret_env_names=required_secret_env_names,
        runtime_profile_sha256=profile.profile_sha256,
        workspace_root_sha256=profile.workspace_root_sha256,
        mcp_fixture_bridge_sha256=(
            profile.mcp_fixture_bridge.bridge_sha256
            if profile.mcp_fixture_bridge is not None
            else None
        ),
    )


def verify_opencode_docker_process(
    *,
    payload: dict[str, object],
    prelaunch: OpenCodePrelaunchContract,
) -> OpenCodeDockerProcessObservation:
    """Verify independent Docker inspect state without persisting secret values."""

    config = payload.get("Config")
    if not isinstance(config, dict):
        raise ValueError("Docker OpenCode inspect payload lacks Config")

    failures: list[str] = []
    entrypoint = config.get("Entrypoint")
    if entrypoint not in (None, []):
        failures.append("entrypoint")

    command = config.get("Cmd")
    if not isinstance(command, list) or not all(
        isinstance(value, str) for value in command
    ):
        failures.append("command_shape")
        observed_command: list[str] = []
    else:
        observed_command = command
        if tuple(command) != prelaunch.command:
            failures.append("command")

    working_directory = config.get("WorkingDir")
    if working_directory != prelaunch.cwd:
        failures.append("working_directory")

    raw_environment = config.get("Env")
    environment_values: dict[str, list[str]] = {}
    if not isinstance(raw_environment, list) or not all(
        isinstance(value, str) and "=" in value for value in raw_environment
    ):
        failures.append("environment_shape")
    else:
        for item in raw_environment:
            name, value = item.split("=", 1)
            environment_values.setdefault(name, []).append(value)

        for name, expected in prelaunch.public_environment.items():
            if environment_values.get(name) != [expected]:
                failures.append(f"public_environment:{name}")
        for name in prelaunch.required_secret_env_names:
            values = environment_values.get(name)
            if values is None or len(values) != 1 or not values[0]:
                failures.append(f"secret_environment:{name}")

    if failures:
        raise ValueError(
            "Docker OpenCode process verification failed closed: "
            + ", ".join(sorted(failures))
        )

    return OpenCodeDockerProcessObservation(
        prelaunch_contract_sha256=prelaunch.contract_sha256,
        command_sha256=canonical_json_hash(observed_command),
        working_directory_sha256=sha256(prelaunch.cwd.encode()).hexdigest(),
        public_environment_sha256=canonical_json_hash(prelaunch.public_environment),
        secret_environment_names_sha256=canonical_json_hash(
            sorted(prelaunch.required_secret_env_names)
        ),
        entrypoint_empty=True,
    )


def bind_attested_opencode_launch(
    *,
    prelaunch: OpenCodePrelaunchContract,
    sandbox_policy: AgentSandboxPolicy,
    launch_plan: OpenCodeLaunchPlan,
) -> OpenCodeAttestedLaunchBinding:
    """Fail closed unless post-launch evidence describes the predeclared process policy."""

    comparisons = {
        "cwd": launch_plan.cwd == prelaunch.cwd,
        "command": launch_plan.command == prelaunch.command,
        "public_environment": (
            launch_plan.public_environment == prelaunch.public_environment
        ),
        "required_secret_env_names": (
            launch_plan.required_secret_env_names == prelaunch.required_secret_env_names
        ),
        "runtime_profile_sha256": (
            launch_plan.runtime_profile_sha256 == prelaunch.runtime_profile_sha256
        ),
        "workspace_root_sha256": (
            launch_plan.workspace_root_sha256 == prelaunch.workspace_root_sha256
        ),
        "mcp_fixture_bridge_sha256": (
            launch_plan.mcp_fixture_bridge_sha256 == prelaunch.mcp_fixture_bridge_sha256
        ),
        "sandbox_policy_sha256": (
            launch_plan.sandbox_policy_sha256 == sandbox_policy.policy_sha256
        ),
    }
    failures = sorted(name for name, matches in comparisons.items() if not matches)
    if failures:
        raise ValueError(
            "attested OpenCode launch differs from prelaunch contract: "
            + ", ".join(failures)
        )
    return OpenCodeAttestedLaunchBinding(
        prelaunch_contract_sha256=prelaunch.contract_sha256,
        sandbox_policy_sha256=sandbox_policy.policy_sha256,
        launch_plan_sha256=launch_plan.launch_sha256,
        target_policy_sha256=launch_plan.target_policy_sha256,
    )
