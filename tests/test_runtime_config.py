from pathlib import Path

import pytest

from llm_redteam.runtime_config import load_budget_config


def test_repository_budget_config_is_strict_and_loadable() -> None:
    config = load_budget_config(Path("config/budgets.yaml"))
    name, budget = config.profile()

    assert name == "smoke"
    assert budget.max_attacks > 0
    assert config.policy.unrestricted_profile_allowed is False


def test_unknown_budget_profile_fails_closed() -> None:
    config = load_budget_config(Path("config/budgets.yaml"))

    with pytest.raises(ValueError, match="unknown budget profile"):
        config.profile("does-not-exist")
