"""Target adapters normalize Blue systems behind one contract."""

from .base import TargetAdapter, TargetRequest, TargetResponse
from .mock import HardenedVaultTarget, VulnerableVaultTarget
from .mock_image import MockImageDisposition, ScriptedImageTarget
from .mock_multiturn import EscalatingVaultTarget
from .opencode import OpenCodeConfig, OpenCodeTarget

__all__ = [
    "EscalatingVaultTarget",
    "HardenedVaultTarget",
    "MockImageDisposition",
    "OpenCodeConfig",
    "OpenCodeTarget",
    "ScriptedImageTarget",
    "TargetAdapter",
    "TargetRequest",
    "TargetResponse",
    "VulnerableVaultTarget",
]
