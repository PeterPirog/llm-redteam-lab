"""Ollama-specific model artifact provenance from the local model inventory.

Ollama's local-model inventory exposes a SHA-256 digest for each model. Ollama server
code derives that summary digest from the stored manifest, so this adapter treats it as
the provider-reported artifact identity. Runtime prompt/template/options remain separate
Blue configuration and must not be conflated with this artifact proof.
"""

from __future__ import annotations

import re

from pydantic import Field

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_artifact import ModelArtifactIdentity, ModelArtifactObservation

_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PREFIXED_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class OllamaArtifactContract(StrictModel):
    """Predeclared local Ollama model identity required for a comparable trial."""

    version: int = Field(ge=1, default=1)
    model_id: str = Field(min_length=1, max_length=256)
    expected_manifest_digest: str
    require_local: bool = True

    @property
    def manifest_digest(self) -> str:
        return _canonical_digest(self.expected_manifest_digest)

    @property
    def contract_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "model_id": self.model_id,
                "expected_manifest_digest": self.manifest_digest,
                "require_local": self.require_local,
            }
        )

    def verify_tags_response(self, payload: object) -> ModelArtifactObservation:
        """Resolve exactly one local model record and require the declared manifest digest."""

        if not isinstance(payload, dict):
            raise ValueError("Ollama tags response must be a JSON object")
        models = payload.get("models")
        if not isinstance(models, list):
            raise ValueError("Ollama tags response must contain a models list")

        matches: list[dict[str, object]] = []
        for item in models:
            if not isinstance(item, dict):
                continue
            if item.get("name") == self.model_id or item.get("model") == self.model_id:
                matches.append(item)
        if len(matches) != 1:
            raise ValueError("Ollama inventory must resolve exactly one declared model")

        record = matches[0]
        remote_model = record.get("remote_model")
        remote_host = record.get("remote_host")
        local_artifact = not bool(remote_model) and not bool(remote_host)
        if self.require_local and not local_artifact:
            raise ValueError("Ollama artifact contract requires a local model, not remote proxy")

        digest_value = record.get("digest")
        if not isinstance(digest_value, str):
            raise ValueError("Ollama model record is missing a SHA-256 digest")
        observed_digest = _canonical_digest(digest_value)
        if observed_digest != self.manifest_digest:
            raise ValueError("Ollama model manifest digest does not match predeclared artifact")

        size = record.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("Ollama model record has invalid artifact size")
        details = record.get("details")
        if details is None:
            details = {}
        if not isinstance(details, dict):
            raise ValueError("Ollama model details must be a JSON object")

        identity = ModelArtifactIdentity(
            provider_id="ollama",
            model_id=self.model_id,
            artifact_digest=observed_digest,
            artifact_size_bytes=size,
            local_artifact=local_artifact,
            format=_optional_string(details.get("format")),
            family=_optional_string(details.get("family")),
            parameter_size=_optional_string(details.get("parameter_size")),
            quantization_level=_optional_string(details.get("quantization_level")),
        )
        return ModelArtifactObservation(
            identity=identity,
            source_kind="ollama:/api/tags",
            source_response_sha256=canonical_json_hash(payload),
        )


def _canonical_digest(value: str) -> str:
    normalized = value.strip().casefold()
    if _BARE_SHA256.fullmatch(normalized):
        return "sha256:" + normalized
    if _PREFIXED_SHA256.fullmatch(normalized):
        return normalized
    raise ValueError("Ollama model digest must be an exact SHA-256 digest")


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
