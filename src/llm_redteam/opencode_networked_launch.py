"""Attested OpenCode launch policy bound to one isolated HAL model peer."""

from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .opencode_model_peer import OpenCodeModelPeerBinding
from .opencode_runtime import (
    AgentSandboxAttestation,
    AgentSandboxPolicy,
    OpenCodeLaunchPlan,
    OpenCodeRuntimeProfile,
)
from .targets.opencode import OpenCodeConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class NetworkedOpenCodeLaunchPlan(OpenCodeLaunchPlan):
    """Per-run plan whose stable target identity includes the exact model-peer binding."""

    model_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    networked_launch_policy_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def target_policy_sha256(self) -> str:
        return canonical_json_hash(
            {
                "base_target_policy_sha256": super().target_policy_sha256,
                "model_binding_sha256": self.model_binding_sha256,
                "networked_launch_policy_sha256": self.networked_launch_policy_sha256,
            }
        )


class OpenCodeNetworkedLaunchPolicy(StrictModel):
    """Stable application launch policy bound to one exact isolated model peer."""

    version: int = Field(ge=1, default=1)
    runtime: OpenCodeRuntimeProfile
    model_binding: OpenCodeModelPeerBinding

    @property
    def config_document(self) -> dict[str, object]:
        return self.model_binding.merge_config(self.runtime.config_document())

    @property
    def config_json(self) -> str:
        return json.dumps(
            self.config_document,
            separators=(",", ":"),
            ensure_ascii=True,
            sort_keys=True,
        )

    @property
    def public_environment(self) -> dict[str, str]:
        return {
            "OPENCODE_AUTO_SHARE": "false",
            "OPENCODE_DISABLE_AUTOUPDATE": "true",
            "OPENCODE_CONFIG_CONTENT": self.config_json,
        }

    @property
    def required_secret_env_names(self) -> tuple[str, ...]:
        if self.runtime.server_password_env is None:
            return ()
        return (self.runtime.server_password_env,)

    @property
    def command(self) -> tuple[str, ...]:
        return (
            self.runtime.executable,
            "--pure",
            "serve",
            "--hostname",
            self.runtime.hostname,
            "--port",
            str(self.runtime.port),
        )

    @property
    def policy_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "runtime_profile_sha256": self.runtime.profile_sha256,
                "model_binding_sha256": self.model_binding.binding_sha256,
                "config_sha256": sha256(self.config_json.encode()).hexdigest(),
                "command": list(self.command),
                "public_environment": self.public_environment,
                "required_secret_env_names": list(self.required_secret_env_names),
            }
        )

    def validate_target_config(self, config: OpenCodeConfig) -> None:
        """Require target selection to name the peer bound into the launch policy."""

        self.model_binding.validate_target_config(config)
        if config.workspace_root != self.runtime.workspace_root:
            raise ValueError("OpenCode target workspace does not match networked runtime")
        if config.password_env != self.runtime.server_password_env:
            raise ValueError("OpenCode target password env does not match networked runtime")

    def build_attested_plan(
        self,
        *,
        sandbox_policy: AgentSandboxPolicy,
        attestation: AgentSandboxAttestation,
    ) -> NetworkedOpenCodeLaunchPlan:
        """Bind application launch material to independently issued sandbox evidence."""

        if attestation.runtime_profile_sha256 != self.runtime.profile_sha256:
            raise ValueError("sandbox attestation does not bind the requested runtime profile")
        if attestation.sandbox_policy_sha256 != sandbox_policy.policy_sha256:
            raise ValueError("sandbox attestation does not bind the requested sandbox policy")
        if attestation.workspace_root_sha256 != self.runtime.workspace_root_sha256:
            raise ValueError("sandbox attestation workspace does not match runtime profile")

        missing: list[str] = []
        if not sandbox_policy.disposable_workspace:
            missing.append("disposable_workspace")
        if not sandbox_policy.external_network_denied:
            missing.append("external_network_denied")
        if not sandbox_policy.git_publication_denied:
            missing.append("git_publication_denied")
        if missing:
            raise ValueError(
                "sandbox policy is insufficient for restricted campaign: "
                + ", ".join(missing)
            )

        return NetworkedOpenCodeLaunchPlan(
            cwd=self.runtime.workspace_root,
            command=self.command,
            public_environment=self.public_environment,
            required_secret_env_names=self.required_secret_env_names,
            runtime_profile_sha256=self.runtime.profile_sha256,
            sandbox_policy_sha256=sandbox_policy.policy_sha256,
            sandbox_attestation_sha256=attestation.attestation_sha256,
            workspace_root_sha256=self.runtime.workspace_root_sha256,
            mcp_fixture_bridge_sha256=(
                self.runtime.mcp_fixture_bridge.bridge_sha256
                if self.runtime.mcp_fixture_bridge is not None
                else None
            ),
            model_binding_sha256=self.model_binding.binding_sha256,
            networked_launch_policy_sha256=self.policy_sha256,
        )
