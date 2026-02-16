"""
CatoScan

A read-only CIS benchmark audit tool for Linux systems.
Provides automated security configuration auditing with support
for both desktop and server environments via profile-driven adapters.
"""

__version__ = "3.5.0"
__author__ = "CatoScan Project"

from .core.detector import (
    EnvironmentDetector,
    EnvironmentType,
    DetectionResult,
    detect_environment,
)
from .core.platform import (
    DistroInfo,
    PlatformContext,
    get_platform_context,
    list_available_profiles,
    profile_exists,
    load_platform_context,
    parse_os_release,
)

__all__ = [
    "EnvironmentDetector",
    "EnvironmentType",
    "DetectionResult",
    "detect_environment",
    "DistroInfo",
    "PlatformContext",
    "get_platform_context",
    "list_available_profiles",
    "profile_exists",
    "load_platform_context",
    "parse_os_release",
]
