"""Exact OpenCode provider binding for one isolated HAL model peer.

The Docker model-network profile proves which model-service endpoint belongs to the
isolated AGENT topology. This module binds OpenCode provider configuration to that exact
network profile, provider ID, model ID and endpoint. Provider syntax is selected
explicitly; it is never inferred from an application-version string.
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlparse

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .docker_model_network import DockerIsolatedModelNetworkProfile
from .domain import StrictModel
from .targets.opencode import OpenCodeConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class OpenCodeProviderConfigDialect(StrEnum):
    """Supported OpenCode provider configuration schemas."""

    PROVIDER_V1 = "provider_v1"
    PROVIDERS_V2 = "providers_v2"


class OpenCodeModelPeerBinding(StrictModel):
    """Stable provider/model binding to one exact isolated model-network profile."""

    version: int = Field(ge=1, default=1)
    model_network_profile_sha256: str = Field(pattern=_HASH_PATTERN)
    provider_id: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=256)
    endpoint_origin: str = Field(min_length=1)
    dialect: OpenCodeProviderConfigDialect = OpenCodeProviderConfigDialect.PROVIDER_V1

    @model_validator(mode="after")
    def endpoint_is_plain_http_origin(self) -> OpenCodeModelPeerBinding:
        parsed = urlparse(self.endpoint_origin)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("model peer endpoint has an invalid port") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname is None
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("model peer endpoint must be a credential-free HTTP origin with port")
        return self

    @classmethod
    def from_network(
        cls,
        *,
        network: DockerIsolatedModelNetworkProfile,
        provider_id: str,
        model_id: str,
        dialect: OpenCodeProviderConfigDialect = OpenCodeProviderConfigDialect.PROVIDER_V1,
    ) -> OpenCodeModelPeerBinding:
        return cls(
            model_network_profile_sha256=network.profile_sha256,
            provider_id=provider_id,
            model_id=model_id,
            endpoint_origin=network.model_endpoint_origin,
            dialect=dialect,
        )

    @property
    def base_url(self) -> str:
        return self.endpoint_origin.rstrip("/") + "/v1"

    @property
    def binding_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))

    def validate_network(self, network: DockerIsolatedModelNetworkProfile) -> None:
        """Require the supplied topology to be exactly the one named by the binding."""

        if network.profile_sha256 != self.model_network_profile_sha256:
            raise ValueError("OpenCode model binding does not bind the requested model network")
        if network.model_endpoint_origin != self.endpoint_origin:
            raise ValueError("OpenCode model binding endpoint does not match the model network")

    def provider_config_fragment(self) -> dict[str, object]:
        """Render only the provider section for the explicitly selected schema."""

        if self.dialect == OpenCodeProviderConfigDialect.PROVIDER_V1:
            return {
                "provider": {
                    self.provider_id: {
                        "npm": "@ai-sdk/openai-compatible",
                        "name": "Isolated HAL model",
                        "options": {"baseURL": self.base_url},
                        "models": {self.model_id: {"name": self.model_id}},
                    }
                }
            }
        return {
            "providers": {
                self.provider_id: {
                    "name": "Isolated HAL model",
                    "package": "@opencode/ai/providers/openai-compatible",
                    "settings": {"baseURL": self.base_url},
                    "models": {self.model_id: {"modelID": self.model_id}},
                }
            }
        }

    def merge_config(self, base: dict[str, object]) -> dict[str, object]:
        """Add provider policy without silently replacing an existing provider section."""

        fragment = self.provider_config_fragment()
        overlap = set(base).intersection(fragment)
        if overlap:
            raise ValueError(
                "OpenCode runtime config already defines provider section: "
                + ", ".join(sorted(overlap))
            )
        return {**base, **fragment}

    def validate_target_config(self, config: OpenCodeConfig) -> None:
        """Require target messages to select the same provider/model as the peer."""

        if config.model_provider_id != self.provider_id:
            raise ValueError("OpenCode target provider does not match isolated model peer")
        if config.model_id != self.model_id:
            raise ValueError("OpenCode target model does not match isolated model peer")
        if config.application_version is None:
            raise ValueError("networked OpenCode target requires an application_version")
