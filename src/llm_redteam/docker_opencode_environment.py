"""Independent runtime environment attestation for a networked OpenCode AGENT.

Launch profiles describe intended state. Measurement-grade execution additionally needs
independent evidence that the running container received that state. This module inspects
the owned Docker container and emits only hash-safe, redacted evidence. Secret values are
used only for an in-memory presence check; they are never retained, hashed or serialized.
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
    """Redacted proof that one owned AGENT matches its declared launch profile."""

    version: int = Field(ge=1, default=1)
    container_id_sha256: str = Field(pattern=_HASH_PATTERN)
    profile_sha256: str = Field(pattern=_HASH_PATTERN)
    launch_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    model_network_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    command_sha256: str = Field(pattern=_HASH_PATTERN)
    public_environment_sha256: str = Field(pattern=_HASH_PATTERN)
    required_secret_names_sha256: str = Field(pattern=_HASH_PATTERN)
    redacted_observation_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


class DockerNetworkedOpenCodeEnvironmentAttestor:
    """Verify the running Docker AGENT without persisting secret environment values."""

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
        """Fail closed unless lease, network, command and environment all agree."""

        _validate_lease_profile_binding(lease=lease, profile=profile)
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
        observed_public, present_secret_names = _redacted_environment_evidence(
            raw_environment,
            expected_public=profile.public_environment,
            required_secret_names=profile.required_secret_env_names,
        )
        if observed_public != profile.public_environment:
            mismatched = sorted(
                name
                for name, expected in profile.public_environment.items()
                if observed_public.get(name) != expected
            )
            raise RuntimeError(
                "networked OpenCode public environment mismatch: " + ", ".join(mismatched)
            )
        missing_secrets = sorted(
            set(profile.required_secret_env_names).difference(present_secret_names)
        )
        if missing_secrets:
            raise RuntimeError(
                "networked OpenCode required secret is absent: " + ", ".join(missing_secrets)
            )

        redacted = {
            "container_id_sha256": container_id_sha256,
            "profile_sha256": profile.profile_sha256,
            "launch_policy_sha256": profile.launch_policy_sha256,
            "model_network_profile_sha256": profile.model_network_profile_sha256,
            "command": list(observed_command),
            "public_environment": {
                name: observed_public[name] for name in sorted(observed_public)
            },
            "present_secret_names": sorted(present_secret_names),
        }
        return DockerNetworkedOpenCodeEnvironmentObservation(
            container_id_sha256=container_id_sha256,
            profile_sha256=profile.profile_sha256,
            launch_policy_sha256=profile.launch_policy_sha256,
            model_network_profile_sha256=profile.model_network_profile_sha256,
            command_sha256=canonical_json_hash(list(observed_command)),
            public_environment_sha256=canonical_json_hash(observed_public),
            required_secret_names_sha256=canonical_json_hash(
                sorted(profile.required_secret_env_names)
            ),
            redacted_observation_sha256=canonical_json_hash(redacted),
        )


def _validate_lease_profile_binding(
    *,
    lease: DockerNetworkedAgentLease,
    profile: DockerNetworkedOpenCodeAgentProfile,
) -> None:
    network = lease.network_attestation
    if network.network_profile_sha256 != profile.model_network_profile_sha256:
        raise ValueError("OpenCode AGENT profile does not match lease model-network attestation")
    if network.agent_container_id_sha256 != lease.container_id_sha256:
        raise ValueError("OpenCode AGENT lease contains inconsistent container identity")
    if network.network_id_sha256 != lease.network_id_sha256:
        raise ValueError("OpenCode AGENT lease contains inconsistent network identity")
    if network.model_endpoint_origin_sha256 != profile.model_endpoint_origin_sha256:
        raise ValueError("OpenCode AGENT profile endpoint does not match network attestation")


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


def _redacted_environment_evidence(
    values: list[object],
    *,
    expected_public: dict[str, str],
    required_secret_names: tuple[str, ...],
) -> tuple[dict[str, str], frozenset[str]]:
    """Extract only public values and secret-name presence from Docker ``Config.Env``."""

    seen: set[str] = set()
    public: dict[str, str] = {}
    present_secrets: set[str] = set()
    secret_names = set(required_secret_names)
    for raw in values:
        if not isinstance(raw, str) or "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        if name in seen:
            raise RuntimeError(f"duplicate Docker environment name: {name}")
        seen.add(name)
        if name in expected_public:
            public[name] = value
        elif name in secret_names and value:
            # Deliberately discard the value immediately. Its content must not enter evidence.
            present_secrets.add(name)
    return public, frozenset(present_secrets)
