"""Target adapters normalize Blue systems behind one contract."""

from .base import TargetAdapter, TargetRequest, TargetResponse
from .comfyui import ComfyUIConfig, ComfyUIInputBinding, ComfyUITarget
from .mock import HardenedVaultTarget, VulnerableVaultTarget
from .mock_image import MockImageDisposition, ScriptedImageTarget
from .mock_multiturn import EscalatingVaultTarget
from .opencode import OpenCodeConfig, OpenCodeTarget
from .state_verified import StateVerifyingTarget

__all__ = [
    "ComfyUIConfig",
    "ComfyUIInputBinding",
    "ComfyUITarget",
    "EscalatingVaultTarget",
    "HardenedVaultTarget",
    "MockImageDisposition",
    "OpenCodeConfig",
    "OpenCodeTarget",
    "ScriptedImageTarget",
    "StateVerifyingTarget",
    "TargetAdapter",
    "TargetRequest",
    "TargetResponse",
    "VulnerableVaultTarget",
]
