"""Provider-neutral binding of model roles to exact model artifacts.

Role configuration and model weights are separate pieces of measurement identity.
A mutable model tag such as ``latest`` can keep the same role configuration while
resolving to different weights. This module binds a resolved role configuration to
one independently observed ``ModelArtifactIdentity`` without hard-coding providers or
model names into business logic.

The binding is intended for Red/Judge/forensic provenance. It does not replace Blue
``TargetIdentity`` and it does not grant permission to invoke a model.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from pydantic import Field, model_validator

from .agent_actions import canonical_json_hash
from .domain import StrictModel
from .model_artifact import ModelArtifactIdentity
from .model_roles import ModelLocation, ModelRole, ModelRoleConfig, ModelsConfig

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_VARIANT_PATTERN = r"^[a-z0-9][a-z0-9_.:-]*$"
_RED_ROLES = frozenset({ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR})


class ModelRoleQualificationRequest(StrictModel):
    """One role route that must be resolved and artifact-qualified."""

    role: ModelRole
    attacker_variant_id: str | None = Field(
        default=None,
        max_length=64,
        pattern=_VARIANT_PATTERN,
    )
    required_capabilities: frozenset[str] = frozenset()

    @model_validator(mode="after")
    def attacker_variant_is_red_only(self) -> ModelRoleQualificationRequest:
        if self.attacker_variant_id is not None and self.role not in _RED_ROLES:
            raise ValueError("attacker_variant_id is valid only for Red model roles")
        return self

    @property
    def route_id(self) -> str:
        return _route_id(self.role, self.attacker_variant_id)


class QualifiedModelRoleIdentity(StrictModel):
    """Stable identity of one resolved model role plus one exact model artifact."""

    version: int = Field(ge=1, default=1)
    role: ModelRole
    attacker_variant_id: str | None = Field(
        default=None,
        max_length=64,
        pattern=_VARIANT_PATTERN,
    )
    provider_id: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=256)
    role_configuration_fingerprint: str = Field(pattern=_HASH_PATTERN)
    artifact_identity_sha256: str = Field(pattern=_HASH_PATTERN)
    artifact_digest: str = Field(pattern=_SHA256_PATTERN)
    local_artifact: bool

    @model_validator(mode="after")
    def attacker_variant_is_red_only(self) -> QualifiedModelRoleIdentity:
        if self.attacker_variant_id is not None and self.role not in _RED_ROLES:
            raise ValueError("attacker_variant_id is valid only for Red model roles")
        return self

    @property
    def route_id(self) -> str:
        return _route_id(self.role, self.attacker_variant_id)

    @property
    def qualification_sha256(self) -> str:
        """Content hash used when composing immutable policy provenance."""

        return canonical_json_hash(self.model_dump(mode="json"))

    def descriptor(self) -> dict[str, object]:
        """Compact hash-safe descriptor suitable for policy fingerprints."""

        return {
            "route_id": self.route_id,
            "provider": self.provider_id,
            "model": self.model_id,
            "role_configuration_fingerprint": self.role_configuration_fingerprint,
            "artifact_identity_sha256": self.artifact_identity_sha256,
            "artifact_digest": self.artifact_digest,
            "local_artifact": self.local_artifact,
            "qualification_sha256": self.qualification_sha256,
        }


class QualifiedModelRoleSet(StrictModel):
    """Order-independent set of exact role/artifact identities for one policy."""

    version: int = Field(ge=1, default=1)
    identities: tuple[QualifiedModelRoleIdentity, ...] = ()

    @model_validator(mode="after")
    def routes_are_unique(self) -> QualifiedModelRoleSet:
        route_ids = [identity.route_id for identity in self.identities]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("qualified model-role routes must be unique")
        return self

    @property
    def ordered_identities(self) -> tuple[QualifiedModelRoleIdentity, ...]:
        return tuple(sorted(self.identities, key=lambda identity: identity.route_id))

    @property
    def route_ids(self) -> tuple[str, ...]:
        return tuple(identity.route_id for identity in self.ordered_identities)

    @property
    def set_sha256(self) -> str:
        return canonical_json_hash(
            {
                "version": self.version,
                "roles": [
                    {
                        "route_id": identity.route_id,
                        "qualification_sha256": identity.qualification_sha256,
                    }
                    for identity in self.ordered_identities
                ],
            }
        )

    def identity_for(
        self,
        role: ModelRole,
        *,
        attacker_variant_id: str | None = None,
    ) -> QualifiedModelRoleIdentity:
        route_id = _route_id(role, attacker_variant_id)
        for identity in self.identities:
            if identity.route_id == route_id:
                return identity
        raise ValueError(f"qualified model-role route not found: {route_id}")

    def descriptor(self) -> dict[str, object]:
        return {
            "version": self.version,
            "set_sha256": self.set_sha256,
            "roles": [identity.descriptor() for identity in self.ordered_identities],
        }


def qualify_model_role(
    *,
    role: ModelRole,
    config: ModelRoleConfig,
    artifact: ModelArtifactIdentity,
    attacker_variant_id: str | None = None,
) -> QualifiedModelRoleIdentity:
    """Fail closed unless role configuration and artifact name the same runtime model."""

    if attacker_variant_id is not None and role not in _RED_ROLES:
        raise ValueError("attacker_variant_id is valid only for Red model roles")
    if not config.enabled:
        raise ValueError(f"cannot qualify disabled model role: {_route_id(role, attacker_variant_id)}")
    if config.provider != artifact.provider_id:
        raise ValueError("model-role provider does not match artifact provider")
    if config.model != artifact.model_id:
        raise ValueError("model-role model ID does not match artifact model ID")

    expected_local = config.location == ModelLocation.LOCAL
    if artifact.local_artifact != expected_local:
        raise ValueError("model-role location does not match artifact locality")

    return QualifiedModelRoleIdentity(
        role=role,
        attacker_variant_id=attacker_variant_id,
        provider_id=artifact.provider_id,
        model_id=artifact.model_id,
        role_configuration_fingerprint=config.configuration_fingerprint,
        artifact_identity_sha256=artifact.identity_sha256,
        artifact_digest=artifact.artifact_digest,
        local_artifact=artifact.local_artifact,
    )


def qualify_model_roles(
    *,
    models: ModelsConfig,
    artifacts: Mapping[tuple[str, str], ModelArtifactIdentity],
    requests: Iterable[ModelRoleQualificationRequest],
) -> QualifiedModelRoleSet:
    """Resolve configured routes and bind each to a pre-verified artifact identity.

    ``artifacts`` is keyed by ``(provider_id, model_id)``. Provider-specific inventory
    verification happens before this function; this layer intentionally consumes only
    provider-neutral ``ModelArtifactIdentity`` objects.
    """

    identities: list[QualifiedModelRoleIdentity] = []
    for request in requests:
        config = models.resolve_role_config(
            request.role,
            attacker_variant_id=request.attacker_variant_id,
            required_capabilities=set(request.required_capabilities),
        )
        key = (config.provider, config.model)
        artifact = artifacts.get(key)
        if artifact is None:
            raise ValueError(
                "verified model artifact missing for role route "
                f"{request.route_id}: {config.provider}/{config.model}"
            )
        identities.append(
            qualify_model_role(
                role=request.role,
                config=config,
                artifact=artifact,
                attacker_variant_id=request.attacker_variant_id,
            )
        )
    return QualifiedModelRoleSet(identities=tuple(identities))


def bind_policy_descriptor_to_model_roles(
    *,
    policy_descriptor: Mapping[str, object],
    qualified_roles: QualifiedModelRoleSet,
    required_route_ids: Iterable[str],
) -> dict[str, object]:
    """Compose exact role-artifact provenance into a policy descriptor.

    This intentionally returns a new mapping. Historical policy descriptors remain
    unchanged unless a caller explicitly opts into artifact-qualified provenance.
    Exact route equality prevents an incomplete or over-broad role set from being
    silently attached to a measurement policy.
    """

    required = tuple(sorted(set(required_route_ids)))
    actual = qualified_roles.route_ids
    if actual != required:
        raise ValueError(
            "qualified model-role routes do not match policy requirement: "
            f"required={required}, actual={actual}"
        )
    if "model_role_artifacts" in policy_descriptor:
        raise ValueError("policy descriptor already contains model_role_artifacts")

    bound = dict(policy_descriptor)
    bound["model_role_artifacts"] = qualified_roles.descriptor()
    return bound


def _route_id(role: ModelRole, attacker_variant_id: str | None) -> str:
    if attacker_variant_id is None:
        return role.value
    return f"{attacker_variant_id}:{role.value}"
