"""Typed role-based model configuration.

Business logic consumes logical roles and capabilities. Concrete model names and
provider endpoints remain runtime configuration so Red/Blue/Judge choices can
change without architectural changes.

Intentional multi-attacker diversity is configured explicitly. ``fallback`` remains an
availability/recovery concept and is never interpreted as an attacker ensemble.
"""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256
from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .domain import StrictModel


class ModelLocation(StrEnum):
    LOCAL = "local"
    CLOUD = "cloud"


class ModelRole(StrEnum):
    RED_PLANNER = "red_planner"
    RED_MUTATOR = "red_mutator"
    JUDGE_SEMANTIC = "judge_semantic"
    JUDGE_MULTIMODAL = "judge_multimodal"
    FORENSIC = "forensic"
    REPORTER = "reporter"


_RED_ROLES = frozenset({ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR})


class ModelPolicy(StrictModel):
    local_first: bool = True
    allow_cloud_fallback: bool = False


class ModelRoleConfig(StrictModel):
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    location: ModelLocation = Field(alias="class")
    capabilities: frozenset[str] = frozenset()
    endpoint: str | None = None
    profile: str | None = None
    api_key_env: str | None = None
    temperature: float = Field(ge=0.0, le=2.0, default=0.0)
    max_output_tokens: int = Field(gt=0, default=800)
    context_tokens: int | None = Field(default=None, gt=0)
    enabled: bool = True
    invoke: str | None = None
    fallback: tuple[str, ...] = ()

    @property
    def configuration_fingerprint(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json", by_alias=True),
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(payload.encode()).hexdigest()


class RedAttackerVariantConfig(StrictModel):
    """One intentional Red planner/mutator configuration in an attacker pool."""

    id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_.:-]*$",
    )
    planner: ModelRoleConfig
    mutator: ModelRoleConfig
    enabled: bool = True
    description: str = ""

    @model_validator(mode="after")
    def required_red_capabilities_exist(self) -> RedAttackerVariantConfig:
        if self.enabled:
            planner_missing = {"text", "reasoning"}.difference(self.planner.capabilities)
            if planner_missing:
                raise ValueError(
                    "attacker planner lacks capabilities: "
                    + ", ".join(sorted(planner_missing))
                )
            mutator_missing = {"text"}.difference(self.mutator.capabilities)
            if mutator_missing:
                raise ValueError(
                    "attacker mutator lacks capabilities: "
                    + ", ".join(sorted(mutator_missing))
                )
        return self

    @property
    def configuration_fingerprint(self) -> str:
        payload = json.dumps(
            {
                "id": self.id,
                "planner": self.planner.configuration_fingerprint,
                "mutator": self.mutator.configuration_fingerprint,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(payload.encode()).hexdigest()

    def role_config(self, role: ModelRole) -> ModelRoleConfig:
        if role == ModelRole.RED_PLANNER:
            return self.planner
        if role == ModelRole.RED_MUTATOR:
            return self.mutator
        raise ValueError(f"attacker variants cannot resolve non-Red role: {role.value}")


class RedAttackerPoolConfig(StrictModel):
    """Explicit attacker-model diversity; separate from provider fallback chains."""

    enabled: bool = False
    variants: tuple[RedAttackerVariantConfig, ...] = ()

    @model_validator(mode="after")
    def enabled_pool_is_distinct_and_nontrivial(self) -> RedAttackerPoolConfig:
        enabled = tuple(variant for variant in self.variants if variant.enabled)
        ids = [variant.id for variant in self.variants]
        if len(set(ids)) != len(ids):
            raise ValueError("red attacker pool variant IDs must be unique")
        if self.enabled and len(enabled) < 2:
            raise ValueError("enabled red attacker pool requires at least two enabled variants")
        fingerprints = [
            (
                variant.planner.configuration_fingerprint,
                variant.mutator.configuration_fingerprint,
            )
            for variant in enabled
        ]
        if len(set(fingerprints)) != len(fingerprints):
            raise ValueError("enabled red attacker variants must use distinct configurations")
        return self

    def variant(self, variant_id: str) -> RedAttackerVariantConfig:
        if not self.enabled:
            raise ValueError("red attacker pool is not enabled")
        for variant in self.variants:
            if variant.id == variant_id:
                if not variant.enabled:
                    raise ValueError(f"red attacker variant is not enabled: {variant_id}")
                return variant
        raise ValueError(f"unknown red attacker variant: {variant_id}")

    @property
    def enabled_variants(self) -> tuple[RedAttackerVariantConfig, ...]:
        if not self.enabled:
            return ()
        return tuple(variant for variant in self.variants if variant.enabled)


class BlueSelection(StrictModel):
    source: str = Field(min_length=1, default="campaign")


class ModelsConfig(StrictModel):
    version: int = Field(ge=1)
    policy: ModelPolicy = ModelPolicy()
    roles: dict[ModelRole, ModelRoleConfig]
    red_attacker_pool: RedAttackerPoolConfig = RedAttackerPoolConfig()
    blue: BlueSelection = BlueSelection()

    @model_validator(mode="after")
    def required_red_roles_and_pool_policy_are_valid(self) -> ModelsConfig:
        for role in _RED_ROLES:
            if role not in self.roles:
                raise ValueError(f"required model role missing: {role.value}")
        for variant in self.red_attacker_pool.enabled_variants:
            self._enforce_location_policy(variant.planner, label=f"{variant.id}:red_planner")
            self._enforce_location_policy(variant.mutator, label=f"{variant.id}:red_mutator")
        return self

    def role(
        self,
        role: ModelRole,
        *,
        required_capabilities: set[str] | None = None,
    ) -> ModelRoleConfig:
        config = self.roles.get(role)
        if config is None or not config.enabled:
            raise ValueError(f"model role is not enabled: {role.value}")
        self._validate_config(
            config,
            label=role.value,
            required_capabilities=required_capabilities,
        )
        return config

    def resolve_role_config(
        self,
        role: ModelRole,
        *,
        attacker_variant_id: str | None = None,
        required_capabilities: set[str] | None = None,
    ) -> ModelRoleConfig:
        """Resolve one role, optionally through an explicit Red attacker variant."""

        if attacker_variant_id is None:
            return self.role(role, required_capabilities=required_capabilities)
        if role not in _RED_ROLES:
            raise ValueError(
                f"attacker_variant_id cannot route non-Red role: {role.value}"
            )
        variant = self.red_attacker_pool.variant(attacker_variant_id)
        config = variant.role_config(role)
        if not config.enabled:
            raise ValueError(
                f"attacker variant role is not enabled: {attacker_variant_id}:{role.value}"
            )
        self._validate_config(
            config,
            label=f"{attacker_variant_id}:{role.value}",
            required_capabilities=required_capabilities,
        )
        return config

    def attacker_variant(self, variant_id: str) -> RedAttackerVariantConfig:
        return self.red_attacker_pool.variant(variant_id)

    def _validate_config(
        self,
        config: ModelRoleConfig,
        *,
        label: str,
        required_capabilities: set[str] | None,
    ) -> None:
        required = required_capabilities or set()
        missing = required.difference(config.capabilities)
        if missing:
            raise ValueError(
                f"model role {label} lacks capabilities: {', '.join(sorted(missing))}"
            )
        self._enforce_location_policy(config, label=label)

    def _enforce_location_policy(self, config: ModelRoleConfig, *, label: str) -> None:
        if (
            self.policy.local_first
            and not self.policy.allow_cloud_fallback
            and config.location == ModelLocation.CLOUD
        ):
            raise ValueError(f"cloud model role {label} blocked by local-first policy")


def load_models_config(path: str | Path) -> ModelsConfig:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"model configuration does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return ModelsConfig.model_validate(raw)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid model configuration {source}: {exc}") from exc
