"""Target adapters normalize Blue systems behind one contract."""

from .base import TargetAdapter, TargetRequest, TargetResponse
from .mock import HardenedVaultTarget, VulnerableVaultTarget

__all__ = [
    "TargetAdapter",
    "TargetRequest",
    "TargetResponse",
    "VulnerableVaultTarget",
    "HardenedVaultTarget",
]
