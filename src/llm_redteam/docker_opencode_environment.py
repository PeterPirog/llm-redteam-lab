"""Independent runtime attestation for a networked OpenCode AGENT launch.

The Docker profile determines which OpenCode command and non-secret environment must be
supplied to the AGENT container.  This module verifies the resulting container state from
`docker inspect` and emits only hash-safe, redacted evidence.  Secret values are checked
for presence but are never retained or hashed.
"""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_networked_opencode_profile import DockerNetworkedOpenCodeAgentProfile
from .docker_networked_supervisor import DockerNetworkedAgentLease
from .docker_supervisor import DockerCommandRunner, SubprocessDockerCommandRunner
from .domain import StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class DockerNetworkedOpenCodeEnvironmentObservation(StrictModel):
    """Hash-only proof that the owned AGENT received the declared launch policy."""

    version: int = Field(ge=1, default=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    command_sha256: str = Field(pattern=_HASH_PATTERN)
    public_environment_sha256: str = Field(pattern=_HASH_PATTERN)
    required_secret_names_sha256: str = Field(pattern=_HASH_PATTERN)
    redacted_observation_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerNetworkedOpenCodeEnvironmentAttestor:
    """Verify application launch state from Docker inspection without exposing secrets."""

    def __init__(
        self,
        runner: DockerCommandRunner | None = None,
        *,
        command_timeout_seconds: float = 15.0,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be positive")
        self._runner = runner or SubprocessDockerCommandRunner()
        self._command_timeout_seconds = command_timeout_seconds

    def observe(
        self,
        *,
        lease: DockerNetworkedAgentLease,
        profile: DockerNetworkedOpenCodeAgentProfile,
    ) -> DockerNetworkedOpenCodeEnvironmentObservation:
        """Fail closed unless command and required environment match the stable profile."""

        result = self._runner.run(
            ("docker", "inspect", "--type", "container", lease.container_name),
            timeout_seconds=self._command_timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError("networked OpenCode environment inspection failed")

        record = _single_inspect_record(result.stdout)
        container_id = _full_container_id(record)
        container_id_sha256 = sha256(container_id.encode()).hexdigest()
        if container_id_sha256 != lease.container_id_sha256:
            raise RuntimeError("networked OpenCode lease no longer owns the inspected container")

        config = record.get("Config")
        if not isinstance(config, dict):
            raise RuntimeError("networked OpenCode inspection lacks Config")

        raw_command = config.get("Cmd")
        if not isinstance(raw_command, list) or not all(
            isinstance(item, str) for item in raw_command
        ):
            raise RuntimeError("networked OpenCode inspection lacks a valid command")
        observed_command = tuple(raw_command)
        if observed_command != profile.launch_command:
            raise RuntimeError("networked OpenCode launch command drifted from profile")

        raw_environment = config.get("Env")
        if not isinstance(raw_environment, list):
            raise RuntimeError("networked OpenCode inspection lacks environment evidence")
        observed_environment = _parse_environment(raw_environment)

        for name, expected in profile.public_environment.items():
            if observed_environment.get(name) != expected:
                raise RuntimeError(
                    f"networked OpenCode public environment mismatch: {name}"
                )
        for name in profile.required_secret_env_names:
            if not observed_environment.get(name):
                raise RuntimeError(
                    f"networked OpenCode required secret is absent: {name}"
                )

        redacted = {
            "container_id_sha256": container_id_sha256,
            "command": list(observed_command),
            "public_environment": {
                name: profile.public_environment[name]
                for name in sorted(profile.public_environment)
            },
            "required_secrets": {
                name: "<present>" for name in sorted(profile.required_secret_env_names)
            },
        }
        return DockerNetworkedOpenCodeEnvironmentObservation(
            container_id_sha256=container_id_sha256,
            profile_sha256=profile.profile_sha256,
            command_sha256=canonical_json_hash(list(observed_command)),
            public_environment_sha256=canonical_json_hash(profile.public_environment),
            required_secret_names_sha256=canonical_json_hash(
                sorted(profile.required_secret_env_names)
            ),
            redacted_observation_sha256=canonical_json_hash(redacted),
        )


def _single_inspect_record(stdout: str) -> dict[str, object]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("networked OpenCode inspection is not valid JSON") from exc
    if not isinstance(payload, list) or len(payload) != 1:
        raise RuntimeError("networked OpenCode inspect must return exactly one record")
    record = payload[0]
    if not isinstance(record, dict):
        raise RuntimeError("networked OpenCode inspect record must be an object")
    return record


def _full_container_id(record: dict[str, object]) -> str:
    value = record.get("Id")
    if not isinstance(value, str):
        raise RuntimeError("networked OpenCode inspect Id must be a string")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("networked OpenCode inspect Id must be a full lowercase ID")
    return value


def _parse_environment(values: list[object]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in values:
        if not isinstance(raw, str) or "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        if name in parsed:
            raise RuntimeError(f"duplicate Docker environment name: {name}")
        parsed[name] = value
    return parsed
