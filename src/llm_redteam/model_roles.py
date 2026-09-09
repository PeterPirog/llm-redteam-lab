"""Typed role-based model configuration.

Business logic consumes logical roles and capabilities. Concrete model names and
provider endpoints remain runtime configuration so Red/Blue/Judge choices can
change without architectural changes.
"""

from __future__ import annotations

from enum import StrEnum
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


class BlueSelection(StrictModel):
    source: str = Field(min_length=1, default="campaign")


class ModelsConfig(StrictModel):
    version: int = Field(ge=1)
    policy: ModelPolicy = ModelPolicy()
    roles: dict[ModelRole, ModelRoleConfig]
    blue: BlueSelection = BlueSelection()

    @model_validator(mode="after")
    def required_red_roles_exist(self) -> ModelsConfig:
        for role in (ModelRole.RED_PLANNER, ModelRole.RED_MUTATOR):
            if role not in self.roles:
                raise ValueError(f"required model role missing: {role.value}")
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
        required = required_capabilities or set()
        missing = required.difference(config.capabilities)
        if missing:
            raise ValueError(
                f"model role {role.value} lacks capabilities: {', '.join(sorted(missing))}"
            )
        if (
            self.policy.local_first
            and not self.policy.allow_cloud_fallback
            and config.location == ModelLocation.CLOUD
        ):
            raise ValueError(f"cloud model role {role.value} blocked by local-first policy")
        return config


def load_models_config(path: str | Path) -> ModelsConfig:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"model configuration does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return ModelsConfig.model_validate(raw)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid model configuration {source}: {exc}") from exc
