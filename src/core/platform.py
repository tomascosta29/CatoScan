"""
Platform abstraction and profile loading for multi-distro support.

This module centralizes OS-level assumptions (package manager, service
manager, common file paths, and remediation templates) behind a config-driven
platform profile model.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import threading
from typing import Any, Optional


_PLATFORMS_DIR = Path(__file__).resolve().parent.parent / "platforms"


@dataclass(frozen=True)
class DistroInfo:
    """Normalized distro information from /etc/os-release."""

    os_id: str
    version_id: str
    id_like: list[str]
    pretty_name: str


@dataclass
class PlatformContext:
    """Runtime platform context with profile-backed helper methods."""

    profile_id: str
    distro: DistroInfo
    profile: dict[str, Any]

    @property
    def package_manager_name(self) -> str:
        """Get package manager name from profile."""
        return str(self.profile.get("package_manager", {}).get("name", "unknown"))

    @property
    def service_manager_name(self) -> str:
        """Get service manager name from profile."""
        return str(self.profile.get("service_manager", {}).get("name", "unknown"))

    def resolve_package_names(self, package: str) -> list[str]:
        """Resolve package aliases for the current distro profile.

        Args:
            package: Logical package name

        Returns:
            Ordered list of package names to try
        """
        aliases = self.profile.get("package_manager", {}).get("package_aliases", {})
        values = aliases.get(package, [])

        resolved = [package]
        for alias in values:
            alias_str = str(alias)
            if alias_str not in resolved:
                resolved.append(alias_str)
        return resolved

    def resolve_service_names(self, service: str) -> list[str]:
        """Resolve service aliases for the current distro profile.

        Args:
            service: Logical service name

        Returns:
            Ordered list of service names to try
        """
        aliases = self.profile.get("service_manager", {}).get("service_aliases", {})
        values = aliases.get(service, [])

        resolved = [service]
        for alias in values:
            alias_str = str(alias)
            if alias_str not in resolved:
                resolved.append(alias_str)
        return resolved

    def check_package_installed(self, package: str) -> tuple[bool, str]:
        """Check if package is installed using profile-configured commands.

        Args:
            package: Package name or logical package key

        Returns:
            Tuple of (installed, method_used)
        """
        package_mgr = self.profile.get("package_manager", {})
        command_specs = package_mgr.get("query_installed", [])

        if not command_specs:
            return False, "none"

        for pkg_name in self.resolve_package_names(package):
            for command_spec in command_specs:
                command, timeout = _normalize_command_spec(command_spec, default_timeout=5)
                rendered = _render_command(command, package=pkg_name)
                result = _run_command(rendered, timeout=timeout)
                if result and result.returncode == 0:
                    return True, self.package_manager_name

        return False, "none"

    def check_service_active(self, service: str) -> tuple[bool, str]:
        """Check whether a service is active.

        Args:
            service: Service unit name (without suffix)

        Returns:
            Tuple of (active, status_output)
        """
        service_mgr = self.profile.get("service_manager", {})
        command_spec = service_mgr.get("is_active")

        if not command_spec:
            return False, "unsupported"

        command, timeout = _normalize_command_spec(command_spec, default_timeout=5)
        last_status = "command failed"

        for service_name in self.resolve_service_names(service):
            rendered = _render_command(command, service=service_name)
            result = _run_command(rendered, timeout=timeout)
            if result is None:
                continue

            status = result.stdout.strip() or result.stderr.strip() or "inactive"
            if result.returncode == 0:
                return True, status
            last_status = status

        return False, last_status

    def check_service_enabled(self, service: str) -> tuple[bool, str]:
        """Check whether a service is enabled.

        Args:
            service: Service unit name (without suffix)

        Returns:
            Tuple of (enabled, status_output)
        """
        service_mgr = self.profile.get("service_manager", {})
        command_spec = service_mgr.get("is_enabled")

        if not command_spec:
            return False, "unsupported"

        command, timeout = _normalize_command_spec(command_spec, default_timeout=5)
        enabled_states = {"enabled", "static", "alias", "indirect"}
        last_status = "command failed"

        for service_name in self.resolve_service_names(service):
            rendered = _render_command(command, service=service_name)
            result = _run_command(rendered, timeout=timeout)
            if result is None:
                continue

            status = result.stdout.strip() or result.stderr.strip() or "disabled"
            if result.returncode == 0 and status in enabled_states:
                return True, status
            last_status = status

        return False, last_status

    def get_default_target(self) -> str:
        """Get default system target from service manager adapter.

        Returns:
            Default target/unit string, or empty string if unavailable
        """
        service_mgr = self.profile.get("service_manager", {})
        command_spec = service_mgr.get("get_default_target")

        if not command_spec:
            return ""

        command, timeout = _normalize_command_spec(command_spec, default_timeout=5)
        result = _run_command(command, timeout=timeout)
        if result is None or result.returncode != 0:
            return ""

        return result.stdout.strip()

    def is_target_active(self, target: str) -> bool:
        """Check whether a target/unit is active.

        Args:
            target: Target or unit name

        Returns:
            True if active, False otherwise
        """
        service_mgr = self.profile.get("service_manager", {})
        command_spec = service_mgr.get("is_target_active")

        if not command_spec:
            return False

        command, timeout = _normalize_command_spec(command_spec, default_timeout=5)
        rendered = _render_command(command, target=target)
        result = _run_command(rendered, timeout=timeout)
        return bool(result and result.returncode == 0)

    def get_paths(self, key: str) -> list[str]:
        """Get path candidates for a logical path key.

        Args:
            key: Logical path key from profile

        Returns:
            Ordered list of candidate paths
        """
        paths = self.profile.get("paths", {})
        values = paths.get(key, [])
        return [str(v) for v in values]

    def render_remediation(self, template_key: str, **kwargs: Any) -> str:
        """Render remediation text from profile templates.

        Args:
            template_key: Key from profile remediation section
            **kwargs: Template variables

        Returns:
            Rendered text or empty string if template not found
        """
        templates = self.profile.get("remediation", {})
        template = templates.get(template_key)
        if not template:
            return ""

        try:
            return str(template).format(**kwargs)
        except (KeyError, ValueError):
            return str(template)


def parse_os_release(file_path: str = "/etc/os-release") -> dict[str, str]:
    """Parse /etc/os-release into a dictionary.

    Args:
        file_path: Path to os-release file

    Returns:
        Parsed key/value map (upper-case keys as in file)
    """
    data: dict[str, str] = {}
    path = Path(file_path)
    if not path.exists():
        return data

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                value = value.strip().strip('"').strip("'")
                data[key.strip()] = value
    except (OSError, UnicodeDecodeError):
        return {}

    return data


def load_platform_context(
    profile_id: Optional[str] = None,
    os_release_path: str = "/etc/os-release",
) -> PlatformContext:
    """Load platform context from profile files and os-release data.

    Args:
        profile_id: Explicit profile id (e.g., "fedora-43")
        os_release_path: Path to os-release file

    Returns:
        PlatformContext instance
    """
    os_release = parse_os_release(os_release_path)
    detected_profile = profile_id or _select_profile_id(os_release)

    base_profile = _load_profile_file("base")
    selected_profile = _load_profile_file(detected_profile)

    # Fallback to Fedora compatibility profile when unknown.
    if not selected_profile and detected_profile != "fedora-43":
        detected_profile = "fedora-43"
        selected_profile = _load_profile_file(detected_profile)

    merged_profile = _deep_merge(base_profile, selected_profile)

    distro = DistroInfo(
        os_id=str(os_release.get("ID", "unknown")).lower(),
        version_id=str(os_release.get("VERSION_ID", "unknown")),
        id_like=[
            token.lower()
            for token in str(os_release.get("ID_LIKE", "")).split()
            if token.strip()
        ],
        pretty_name=str(os_release.get("PRETTY_NAME", "unknown")),
    )

    return PlatformContext(
        profile_id=detected_profile,
        distro=distro,
        profile=merged_profile,
    )


_DEFAULT_CONTEXT: Optional[PlatformContext] = None
_LOCK = threading.Lock()


def list_available_profiles(include_base: bool = False) -> list[str]:
    """List available platform profile IDs from profile directory.

    Args:
        include_base: Whether to include the internal base profile

    Returns:
        Sorted list of profile identifiers
    """
    if not _PLATFORMS_DIR.exists():
        return []

    profiles: list[str] = []
    for path in _PLATFORMS_DIR.glob("*.json"):
        profile_id = path.stem
        if profile_id == "base" and not include_base:
            continue
        profiles.append(profile_id)

    return sorted(profiles)


def profile_exists(profile_id: str) -> bool:
    """Check whether a platform profile file exists."""
    if not profile_id:
        return False
    return (_PLATFORMS_DIR / f"{profile_id}.json").exists()


def get_platform_context(
    profile_id: Optional[str] = None,
    refresh: bool = False,
) -> PlatformContext:
    """Get cached platform context.

    Args:
        profile_id: Optional explicit profile id. If provided, bypasses cache.
        refresh: Reload cached default context

    Returns:
        PlatformContext
    """
    global _DEFAULT_CONTEXT

    if profile_id:
        return load_platform_context(profile_id=profile_id)

    with _LOCK:
        if refresh or _DEFAULT_CONTEXT is None:
            _DEFAULT_CONTEXT = load_platform_context()
        return _DEFAULT_CONTEXT


def _select_profile_id(os_release: dict[str, str]) -> str:
    """Select best profile id based on os-release data."""
    os_id = str(os_release.get("ID", "")).strip().lower()
    version = str(os_release.get("VERSION_ID", "")).strip().lower()
    id_like = [
        token.lower() for token in str(os_release.get("ID_LIKE", "")).split() if token.strip()
    ]

    candidates: list[str] = []
    if os_id and version:
        candidates.append(f"{os_id}-{version}")
    if os_id:
        candidates.append(os_id)

    for like in id_like:
        if like and version:
            candidates.append(f"{like}-{version}")
        if like:
            candidates.append(like)

    for candidate in candidates:
        if (_PLATFORMS_DIR / f"{candidate}.json").exists():
            return candidate

    return "fedora-43"


def _load_profile_file(profile_id: str) -> dict[str, Any]:
    """Load a platform profile JSON file by id."""
    path = _PLATFORMS_DIR / f"{profile_id}.json"
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}

    return {}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two dictionaries."""
    merged: dict[str, Any] = dict(base)

    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


def _normalize_command_spec(
    command_spec: Any,
    default_timeout: int,
) -> tuple[list[str], int]:
    """Normalize command spec to (command, timeout)."""
    if isinstance(command_spec, dict):
        command = command_spec.get("cmd", [])
        timeout = int(command_spec.get("timeout", default_timeout))
    else:
        command = command_spec
        timeout = default_timeout

    if not isinstance(command, list):
        return [], default_timeout

    return [str(part) for part in command], timeout


def _render_command(command: list[str], **kwargs: Any) -> list[str]:
    """Render command template tokens with format placeholders."""
    rendered: list[str] = []
    for part in command:
        try:
            rendered.append(part.format(**kwargs))
        except (KeyError, ValueError):
            rendered.append(part)
    return rendered


def _run_command(command: list[str], timeout: int) -> Optional[subprocess.CompletedProcess[str]]:
    """Run command safely and return CompletedProcess or None on failure."""
    if not command:
        return None

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError):
        return None
