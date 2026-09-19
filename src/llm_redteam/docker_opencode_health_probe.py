"""Hardened ephemeral Docker profile for trusted OpenCode loopback health probing."""

from __future__ import annotations

from pydantic import Field

from .agent_actions import canonical_json_hash
from .docker_model_peer import DockerModelPeerProfile
from .domain import StrictModel
from .opencode_runtime import OpenCodeRuntimeProfile

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_IMAGE_REF_PATTERN = r"^.+@sha256:[0-9a-f]{64}$"
_IMAGE_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_EXECUTABLE = "/usr/local/bin/rt-opencode-probe"


class DockerOpenCodeHealthProbeProfile(StrictModel):
    """Stable policy for one non-persistent health probe sharing AGENT networking."""

    version: int = Field(ge=1, default=1)
    image_ref: str = Field(pattern=_IMAGE_REF_PATTERN)
    image_id: str = Field(pattern=_IMAGE_ID_PATTERN)
    executable: str = _EXECUTABLE
    memory_limit_bytes: int = Field(ge=32 * 1024 * 1024, default=64 * 1024 * 1024)
    pids_limit: int = Field(ge=8, default=32)
    cpus: float = Field(gt=0.0, default=0.25)

    @classmethod
    def from_model_peer(
        cls,
        peer: DockerModelPeerProfile,
    ) -> DockerOpenCodeHealthProbeProfile:
        """Reuse the already digest-pinned laboratory probe image."""

        return cls(image_ref=peer.image_ref, image_id=peer.image_id)

    @property
    def profile_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    def docker_run_command(
        self,
        *,
        agent_container_name: str,
        runtime_profile: OpenCodeRuntimeProfile,
    ) -> tuple[str, ...]:
        """Build a foreground probe command with no secret values in argv."""

        if (
            not agent_container_name
            or any(character.isspace() for character in agent_container_name)
        ):
            raise ValueError(
                "agent_container_name must be non-empty and contain no whitespace"
            )
        endpoint = _opencode_health_endpoint(runtime_profile)
        secret_args: tuple[str, ...] = ()
        if runtime_profile.server_password_env is not None:
            secret_args = ("--env", runtime_profile.server_password_env)
        return (
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            f"container:{agent_container_name}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            str(self.memory_limit_bytes),
            "--cpus",
            str(self.cpus),
            *secret_args,
            "--entrypoint",
            self.executable,
            self.image_ref,
            "health",
            endpoint,
        )


def _opencode_health_endpoint(runtime_profile: OpenCodeRuntimeProfile) -> str:
    hostname = runtime_profile.hostname.strip()
    url_host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    return f"http://{url_host}:{runtime_profile.port}/global/health"
