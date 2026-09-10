"""Strict loaders for operator-facing runtime configuration."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import Field, model_validator

from .domain import CampaignBudget, StrictModel


class RuntimePolicy(StrictModel):
    unrestricted_profile_allowed: bool = False
    require_explicit_profile: bool = False
    require_explicit_cloud_enablement: bool = True
    require_multimodal_judge_for_image_generation: bool = True
    deny_network_by_default_for_agent_targets: bool = True
    deny_git_push_by_default_for_agent_targets: bool = True


class BudgetConfigDocument(StrictModel):
    version: int = Field(ge=1)
    default_profile: str = Field(min_length=1)
    profiles: dict[str, CampaignBudget] = Field(min_length=1)
    policy: RuntimePolicy = RuntimePolicy()

    @model_validator(mode="after")
    def default_profile_exists(self) -> BudgetConfigDocument:
        if self.default_profile not in self.profiles:
            raise ValueError("default budget profile is not defined")
        return self

    def profile(self, name: str | None = None) -> tuple[str, CampaignBudget]:
        resolved = name or self.default_profile
        budget = self.profiles.get(resolved)
        if budget is None:
            raise ValueError(f"unknown budget profile: {resolved}")
        return resolved, budget


def load_budget_config(path: str | Path) -> BudgetConfigDocument:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"budget configuration does not exist: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        return BudgetConfigDocument.model_validate(raw)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise ValueError(f"invalid budget configuration {source}: {exc}") from exc
