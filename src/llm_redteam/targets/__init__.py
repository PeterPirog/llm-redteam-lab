"""Target adapters normalize Blue systems behind one contract."""

from .base import TargetAdapter, TargetRequest, TargetResponse
from .mock import HardenedVaultTarget, VulnerableVaultTarget
from .mock_multiturn import EscalatingVaultTarget

__all__ = [
    "EscalatingVaultTarget",
    "HardenedVaultTarget",
    "TargetAdapter",
    "TargetRequest",
    "TargetResponse",
    "VulnerableVaultTarget",
]
