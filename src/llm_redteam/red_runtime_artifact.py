"""Non-inference exact-artifact recheck for HAL-hosted Red Ollama runtimes.

The stable Red measurement binding is predeclared offline. Immediately before a live
campaign, this module fetches only Ollama /api/tags from the configured local runtime,
requires the exact planner/mutator artifact identities to remain unchanged, and emits
hash-safe execution provenance. It never calls a completion/generation endpoint.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx
from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_inventory import require_local_model_endpoint
from .model_roles import ModelLocation, ModelRole, ModelRoleConfig, ModelsConfig
from .ollama_artifact import OllamaArtifactContract
from .red_artifact_identity import (
    red_artifact_measurement_binding_from_exact_artifacts,
    red_artifact_measurement_binding_sha256,
)
from .reference_artifact_qualification import (
    QualifiedArtifactBinding,
    ReferenceArtifactQualificationReport,
)
from .storage.execution_provenance_repository import (
    ExecutionProvenanceDescriptor,
    build_execution_provenance_descriptor,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"

RED_RUNTIME_ARTIFACT_RECHECK_PROVENANCE_KIND = "red_runtime_artifact_recheck_v1"


@runtime_checkable
class OllamaTagsProbe(Protocol):
    """Acquire one fresh Ollama tags payload without model inference."""

    async def fetch_tags(
        self,
        *,
        inference_endpoint: str,
        label: str,
        allowed_hosts: frozenset[str],
    ) -> object: ...


class HttpxLocalOllamaTagsProbe:
    """Fetch /api/tags only from a loopback or explicitly trusted HAL host."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._owns_client = client is None

    async def fetch_tags(
        self,
        *,
        inference_endpoint: str,
        label: str,
        allowed_hosts: frozenset[str],
    ) -> object:
        require_local_model_endpoint(
            inference_endpoint,
            label=label,
            allowed_hosts=allowed_hosts,
        )
        tags_endpoint = _ollama_tags_endpoint(inference_endpoint)
        try:
            response = await self._client.get(
                tags_endpoint,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"Ollama tags probe returned HTTP {exc.response.status_code}: {label}"
            ) from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Ollama tags probe transport failed for {label}: {type(exc).__name__}"
            ) from exc
        except ValueError as exc:
            raise RuntimeError(f"Ollama tags probe returned invalid JSON: {label}") from exc
        return payload

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class RedRuntimeArtifactRoleObservation(StrictModel):
    """Hash-safe fresh runtime observation for one Red role."""

    role: ModelRole
    model_id: str = Field(min_length=1)
    inference_endpoint_sha256: str = Field(pattern=_HASH_PATTERN)
    tags_endpoint_sha256: str = Field(pattern=_HASH_PATTERN)
    tags_response_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_observation_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_contract_sha256: str = Field(pattern=_HASH_PATTERN)


class RedRuntimeArtifactRecheck(StrictModel):
    """Proof that live HAL Red artifacts still equal the predeclared measurement identity."""

    version: int = Field(ge=1, default=1)
    expected_red_measurement_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    observed_red_measurement_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    observations: tuple[RedRuntimeArtifactRoleObservation, ...]

    @model_validator(mode="after")
    def exact_role_pair_matches_expected_binding(self) -> RedRuntimeArtifactRecheck:
        roles = [observation.role for observation in self.observations]
        if roles != [ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR]:
            raise ValueError(
                "Red runtime artifact recheck must contain planner then mutator exactly once"
            )
        if (
            self.observed_red_measurement_binding_sha256
            != self.expected_red_measurement_binding_sha256
        ):
            raise ValueError("live Red artifact identity differs from predeclared binding")
        return self

    @property
    def proof_sha256(self) -> str:
        return canonical_json_hash(self.model_dump(mode="json"))


async def recheck_red_runtime_artifacts(
    *,
    models: ModelsConfig,
    qualification: ReferenceArtifactQualificationReport,
    expected_red_measurement_binding_sha256: str,
    probe: OllamaTagsProbe,
    allowed_endpoint_hosts: set[str] | frozenset[str] = frozenset(),
) -> RedRuntimeArtifactRecheck:
    """Fail closed unless planner/mutator still resolve to their exact qualified artifacts."""

    planner = models.role(
        ModelRole.RED_PLANNER,
        required_capabilities={"text", "reasoning"},
    )
    mutator = models.role(ModelRole.RED_MUTATOR, required_capabilities={"text"})
    _validate_red_runtime_config(planner, label=ModelRole.RED_PLANNER.value)
    _validate_red_runtime_config(mutator, label=ModelRole.RED_MUTATOR.value)

    expected_binding = red_artifact_measurement_binding_sha256(
        planner_model_id=planner.model,
        planner_configuration_sha256=planner.configuration_fingerprint,
        mutator_model_id=mutator.model,
        mutator_configuration_sha256=mutator.configuration_fingerprint,
        qualification=qualification,
    )
    if expected_binding != expected_red_measurement_binding_sha256:
        raise ValueError(
            "configured Red roles/qualification do not match predeclared measurement binding"
        )

    allowed = frozenset(host.strip().casefold() for host in allowed_endpoint_hosts)
    payload_cache: dict[str, object] = {}
    planner_observation = await _recheck_role(
        role=ModelRole.RED_PLANNER,
        config=planner,
        qualification=qualification,
        probe=probe,
        allowed_hosts=allowed,
        payload_cache=payload_cache,
    )
    mutator_observation = await _recheck_role(
        role=ModelRole.RED_MUTATOR,
        config=mutator,
        qualification=qualification,
        probe=probe,
        allowed_hosts=allowed,
        payload_cache=payload_cache,
    )

    observed_binding = red_artifact_measurement_binding_from_exact_artifacts(
        planner_model_id=planner.model,
        planner_configuration_sha256=planner.configuration_fingerprint,
        planner_artifact_digest=planner_observation.artifact_digest,
        planner_artifact_identity_sha256=planner_observation.artifact_identity_sha256,
        planner_contract_sha256=planner_observation.artifact_contract_sha256,
        mutator_model_id=mutator.model,
        mutator_configuration_sha256=mutator.configuration_fingerprint,
        mutator_artifact_digest=mutator_observation.artifact_digest,
        mutator_artifact_identity_sha256=mutator_observation.artifact_identity_sha256,
        mutator_contract_sha256=mutator_observation.artifact_contract_sha256,
    )
    return RedRuntimeArtifactRecheck(
        expected_red_measurement_binding_sha256=expected_red_measurement_binding_sha256,
        observed_red_measurement_binding_sha256=observed_binding,
        observations=(planner_observation, mutator_observation),
    )


def red_runtime_artifact_recheck_provenance(
    report: RedRuntimeArtifactRecheck,
) -> ExecutionProvenanceDescriptor:
    """Convert a verified live Red recheck into immutable campaign provenance."""

    return build_execution_provenance_descriptor(
        kind=RED_RUNTIME_ARTIFACT_RECHECK_PROVENANCE_KIND,
        payload=report.model_dump(mode="json"),
    )


async def _recheck_role(
    *,
    role: ModelRole,
    config: ModelRoleConfig,
    qualification: ReferenceArtifactQualificationReport,
    probe: OllamaTagsProbe,
    allowed_hosts: frozenset[str],
    payload_cache: dict[str, object],
) -> RedRuntimeArtifactRoleObservation:
    if config.endpoint is None:  # pragma: no cover - validated by caller
        raise RuntimeError("Red runtime endpoint disappeared after validation")

    label = role.value
    endpoint = config.endpoint.strip()
    endpoint_sha256 = require_local_model_endpoint(
        endpoint,
        label=label,
        allowed_hosts=allowed_hosts,
    )
    tags_endpoint = _ollama_tags_endpoint(endpoint)
    cache_key = tags_endpoint
    if cache_key not in payload_cache:
        payload_cache[cache_key] = await probe.fetch_tags(
            inference_endpoint=endpoint,
            label=label,
            allowed_hosts=allowed_hosts,
        )
    payload = payload_cache[cache_key]

    qualified = _qualified_binding(qualification, config.model)
    contract = OllamaArtifactContract(
        model_id=config.model,
        expected_manifest_digest=qualified.artifact_digest,
        require_local=True,
    )
    observation = contract.verify_tags_response(payload)
    if observation.identity.identity_sha256 != qualified.artifact_identity_sha256:
        raise ValueError(
            f"live Red artifact identity differs from qualified artifact: {label}"
        )

    return RedRuntimeArtifactRoleObservation(
        role=role,
        model_id=config.model,
        inference_endpoint_sha256=endpoint_sha256,
        tags_endpoint_sha256=sha256(tags_endpoint.encode()).hexdigest(),
        tags_response_sha256=observation.source_response_sha256,
        artifact_digest=observation.identity.artifact_digest,
        artifact_identity_sha256=observation.identity.identity_sha256,
        artifact_observation_sha256=observation.proof_sha256,
        artifact_contract_sha256=qualified.contract_sha256,
    )


def _validate_red_runtime_config(config: ModelRoleConfig, *, label: str) -> None:
    if config.provider != "ollama":
        raise ValueError(f"live Red artifact recheck requires Ollama role: {label}")
    if config.location != ModelLocation.LOCAL:
        raise ValueError(f"live Red artifact recheck requires local role: {label}")
    if config.endpoint is None:
        raise ValueError(f"live Red artifact recheck requires explicit endpoint: {label}")
    if config.fallback:
        raise ValueError(f"live Red artifact recheck forbids fallback models: {label}")


def _qualified_binding(
    report: ReferenceArtifactQualificationReport,
    model_id: str,
) -> QualifiedArtifactBinding:
    matches = [binding for binding in report.bindings if binding.model_id == model_id]
    if len(matches) != 1:
        raise ValueError(
            f"artifact qualification must contain exactly one binding for model: {model_id}"
        )
    return matches[0]


def _ollama_tags_endpoint(inference_endpoint: str) -> str:
    parsed = urlparse(inference_endpoint.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Ollama inference endpoint is not HTTP(S)")
    return f"{parsed.scheme}://{parsed.netloc}/api/tags"
