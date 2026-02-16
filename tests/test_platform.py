"""
Platform abstraction tests.

Validates profile loading, os-release parsing, and adapter helpers used by
checks to avoid hardcoded distro assumptions.
"""

import sys
from pathlib import Path
from unittest import mock

import pytest

# Add project root to import path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.platform import (
    load_platform_context,
    parse_os_release,
    list_available_profiles,
    profile_exists,
)


class TestOsReleaseParsing:
    """Tests for os-release parsing."""

    def test_parse_os_release_file(self, tmp_path: Path) -> None:
        """Parses key/value pairs from a temporary os-release file."""
        file_path = tmp_path / "os-release"
        file_path.write_text(
            "ID=fedora\n"
            "VERSION_ID=43\n"
            "PRETTY_NAME=Fedora Linux 43\n"
            "ID_LIKE=\"rhel fedora\"\n",
            encoding="utf-8",
        )

        data = parse_os_release(str(file_path))

        assert data["ID"] == "fedora"
        assert data["VERSION_ID"] == "43"
        assert data["PRETTY_NAME"] == "Fedora Linux 43"
        assert data["ID_LIKE"] == "rhel fedora"


class TestPlatformContextLoading:
    """Tests for platform profile loading."""

    def test_load_explicit_fedora_profile(self) -> None:
        """Loads the explicit Fedora profile and merges defaults."""
        context = load_platform_context(
            profile_id="fedora-43",
            os_release_path="/nonexistent/os-release",
        )

        assert context.profile_id == "fedora-43"
        assert context.package_manager_name == "dnf"
        assert context.service_manager_name == "systemd"

    def test_render_remediation_template(self) -> None:
        """Renders remediation command templates from profile data."""
        context = load_platform_context(
            profile_id="fedora-43",
            os_release_path="/nonexistent/os-release",
        )

        command = context.render_remediation("install_packages", packages="firewalld")
        assert command == "sudo dnf install firewalld"

    def test_detects_ubuntu_profile_from_os_release(self, tmp_path: Path) -> None:
        """Selects ubuntu profile automatically from os-release data."""
        os_release = tmp_path / "os-release"
        os_release.write_text(
            "ID=ubuntu\n"
            "VERSION_ID=24.04\n"
            "ID_LIKE=debian\n"
            "PRETTY_NAME=Ubuntu 24.04 LTS\n",
            encoding="utf-8",
        )

        context = load_platform_context(os_release_path=str(os_release))

        assert context.profile_id == "ubuntu-24.04"
        assert context.package_manager_name == "apt"

    def test_profile_helpers(self) -> None:
        """Lists known profiles and validates profile existence checks."""
        profiles = list_available_profiles()
        assert "fedora-43" in profiles
        assert "ubuntu-24.04" in profiles
        assert profile_exists("fedora-43") is True
        assert profile_exists("not-a-real-profile") is False


class TestPlatformAdapters:
    """Tests for package/service adapter behavior."""

    @mock.patch("src.core.platform.subprocess.run")
    def test_check_package_installed_with_fallback(self, mock_run: mock.MagicMock) -> None:
        """Falls back across configured package query commands."""
        context = load_platform_context(
            profile_id="fedora-43",
            os_release_path="/nonexistent/os-release",
        )

        # rpm fails, dnf succeeds
        mock_run.side_effect = [
            mock.MagicMock(returncode=1, stdout="", stderr=""),
            mock.MagicMock(returncode=0, stdout="firewalld\n", stderr=""),
        ]

        installed, method = context.check_package_installed("firewalld")

        assert installed is True
        assert method == "dnf"
        assert mock_run.call_count == 2

    @mock.patch("src.core.platform.subprocess.run")
    def test_check_service_active_and_enabled(self, mock_run: mock.MagicMock) -> None:
        """Checks active/enabled status via platform service adapter."""
        context = load_platform_context(
            profile_id="fedora-43",
            os_release_path="/nonexistent/os-release",
        )

        mock_run.side_effect = [
            mock.MagicMock(returncode=0, stdout="active\n", stderr=""),
            mock.MagicMock(returncode=0, stdout="enabled\n", stderr=""),
        ]

        active, active_status = context.check_service_active("firewalld")
        enabled, enabled_status = context.check_service_enabled("firewalld")

        assert active is True
        assert active_status == "active"
        assert enabled is True
        assert enabled_status == "enabled"

    def test_resolve_ubuntu_package_aliases(self) -> None:
        """Resolves Ubuntu package aliases for Fedora-oriented package keys."""
        context = load_platform_context(
            profile_id="ubuntu-24.04",
            os_release_path="/nonexistent/os-release",
        )

        names = context.resolve_package_names("openldap-servers")

        assert names[0] == "openldap-servers"
        assert "slapd" in names

    @mock.patch("src.core.platform.subprocess.run")
    def test_check_package_installed_uses_aliases(self, mock_run: mock.MagicMock) -> None:
        """Falls back to Ubuntu alias package names during installation checks."""
        context = load_platform_context(
            profile_id="ubuntu-24.04",
            os_release_path="/nonexistent/os-release",
        )

        # Original package key fails; Ubuntu alias succeeds.
        mock_run.side_effect = [
            mock.MagicMock(returncode=1, stdout="", stderr=""),
            mock.MagicMock(returncode=0, stdout="Status: install ok installed\n", stderr=""),
        ]

        installed, method = context.check_package_installed("openldap-servers")

        assert installed is True
        assert method == "apt"
        assert mock_run.call_count == 2

    @mock.patch("src.core.platform.subprocess.run")
    def test_check_service_active_uses_service_aliases(self, mock_run: mock.MagicMock) -> None:
        """Falls back to Ubuntu service aliases during active checks."""
        context = load_platform_context(
            profile_id="ubuntu-24.04",
            os_release_path="/nonexistent/os-release",
        )

        # Check logical service first (httpd), then alias (apache2) succeeds.
        mock_run.side_effect = [
            mock.MagicMock(returncode=3, stdout="inactive\n", stderr=""),
            mock.MagicMock(returncode=0, stdout="active\n", stderr=""),
        ]

        active, status = context.check_service_active("httpd")

        assert active is True
        assert status == "active"
        assert mock_run.call_count == 2
        first_command = mock_run.call_args_list[0].args[0]
        second_command = mock_run.call_args_list[1].args[0]
        assert first_command[-1] == "httpd"
        assert second_command[-1] == "apache2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
