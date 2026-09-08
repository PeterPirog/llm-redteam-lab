"""Core package for llm-redteam-lab."""

from .domain import (
    AttackCase,
    AttackTier,
    CompromiseOutcome,
    TargetClass,
    TargetIdentity,
    TargetMode,
)

__all__ = [
    "AttackCase",
    "AttackTier",
    "CompromiseOutcome",
    "TargetClass",
    "TargetIdentity",
    "TargetMode",
]
