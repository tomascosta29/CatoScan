"""
CatoScan - Core Module

This module contains core functionality for the CIS audit tool.
"""

from .detector import (
    EnvironmentDetector,
    EnvironmentType,
    DetectionResult,
    detect_environment,
)
from .check import (
    BaseCheck,
    CheckResult,
    Severity,
)
from .registry import (
    CheckRegistry,
)
from .platform import (
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
    "BaseCheck",
    "CheckResult",
    "Severity",
    "CheckRegistry",
    "DistroInfo",
    "PlatformContext",
    "get_platform_context",
    "list_available_profiles",
    "profile_exists",
    "load_platform_context",
    "parse_os_release",
]
