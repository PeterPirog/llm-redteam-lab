"""Target adapters normalize Blue systems behind one contract."""

from .base import TargetAdapter, TargetRequest, TargetResponse
from .mock import HardenedVaultTarget, VulnerableVaultTarget
from .mock_multiturn import EscalatingVaultTarget
from .opencode import OpenCodeConfig, OpenCodeTarget

__all__ = [
    "EscalatingVaultTarget",
    "HardenedVaultTarget",
    "OpenCodeConfig",
    "OpenCodeTarget",
    "TargetAdapter",
    "TargetRequest",
    "TargetResponse",
    "VulnerableVaultTarget",
]
