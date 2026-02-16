"""Platform-aware remediation rendering tests.

These tests validate that selected checks render distro-specific remediation
commands when run with a non-default platform profile.
"""

import sys
from pathlib import Path

import pytest

# Add project root to import path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.platform import load_platform_context
from src.checks.network_firewalld import FirewalldCheck
from src.checks.iptables_installed import IPTablesInstalledCheck
from src.checks.boot_grub_password import GrubPasswordCheck
from src.checks.selinux_bootloader import SELinuxBootloaderCheck
from src.checks.audit_grub import AuditGrubCheck
from src.checks.audit_network_changes import AuditNetworkChangesCheck


@pytest.fixture
def ubuntu_context():
    """Load Ubuntu profile context for remediation rendering checks."""
    return load_platform_context(profile_id="ubuntu-24.04", os_release_path="/nonexistent")


def test_firewalld_remediation_uses_profile_package_manager(monkeypatch, ubuntu_context) -> None:
    """Firewalld remediation should use apt commands under Ubuntu profile."""
    check = FirewalldCheck(privileged=True, platform_context=ubuntu_context)

    monkeypatch.setattr(check, "_is_firewalld_installed", lambda: (False, "none"))

    result = check.run()

    assert result.passed is False
    assert "sudo apt-get install -y firewalld" in result.remediation


def test_iptables_remediation_uses_profile_package_manager(monkeypatch, ubuntu_context) -> None:
    """iptables remediation should use apt commands under Ubuntu profile."""
    check = IPTablesInstalledCheck(privileged=True, platform_context=ubuntu_context)

    monkeypatch.setattr(check, "_is_installed", lambda: (False, "none"))
    monkeypatch.setattr(check, "_check_iptables_binary", lambda: False)

    result = check.run()

    assert result.passed is False
    assert "sudo apt-get install -y iptables" in result.remediation


def test_grub_password_remediation_uses_profile_grub_commands(monkeypatch, ubuntu_context) -> None:
    """GRUB password remediation should use Ubuntu grub command variants."""
    check = GrubPasswordCheck(privileged=True, platform_context=ubuntu_context)

    monkeypatch.setattr(check, "_find_grub_cfg", lambda: "/boot/grub/grub.cfg")
    monkeypatch.setattr(
        check,
        "_check_password_in_file",
        lambda _: {
            "file": "/boot/grub/grub.cfg",
            "exists": True,
            "readable": True,
            "has_password_pbkdf2": False,
            "has_password": False,
            "has_superuser": False,
            "password_lines": [],
            "superuser_lines": [],
        },
    )
    monkeypatch.setattr(
        check,
        "_check_grub_d_directory",
        lambda: {
            "directory": "/etc/grub.d",
            "exists": True,
            "files_checked": [],
            "files_with_password": [],
            "has_password_pbkdf2": False,
            "has_password": False,
            "has_superuser": False,
        },
    )
    monkeypatch.setattr(check, "_check_custom_files", lambda: [])

    result = check.run()

    assert result.passed is False
    assert "sudo grub-mkpasswd-pbkdf2" in result.remediation
    assert "sudo grub-mkconfig -o /boot/grub/grub.cfg" in result.remediation


def test_selinux_bootloader_remediation_uses_profile_grub_command(monkeypatch, ubuntu_context) -> None:
    """SELinux bootloader remediation should render Ubuntu grub command."""
    check = SELinuxBootloaderCheck(privileged=True, platform_context=ubuntu_context)

    monkeypatch.setattr(
        check,
        "_check_grub_config",
        lambda: (
            True,
            ["selinux=0"],
            {"files_checked": ["/etc/default/grub"], "disable_params_found": [], "config_lines": []},
        ),
    )

    result = check.run()

    assert result.passed is False
    assert "sudo grub-mkconfig -o /boot/grub/grub.cfg" in result.remediation


def test_audit_grub_remediation_uses_profile_paths_and_command(monkeypatch, ubuntu_context) -> None:
    """Audit GRUB remediation should use profile-aware paths and commands."""
    check = AuditGrubCheck(privileged=True, platform_context=ubuntu_context)

    monkeypatch.setattr(check, "_collect_all_rules", lambda: ["-b 8192"])
    monkeypatch.setattr(
        check,
        "_check_grub_audit",
        lambda: {
            "grub_file": "/etc/default/grub",
            "grub_file_exists": True,
            "audit_in_grub": False,
            "audit_line": None,
        },
    )

    result = check.run()

    assert result.passed is False
    assert "Add to /etc/default/grub in GRUB_CMDLINE_LINUX:" in result.remediation
    assert "Then run: sudo grub-mkconfig -o /boot/grub/grub.cfg" in result.remediation


def test_audit_network_changes_remediation_uses_profile_watch_paths(monkeypatch, ubuntu_context) -> None:
    """Audit network remediation should include profile-derived watch targets."""
    check = AuditNetworkChangesCheck(privileged=True, platform_context=ubuntu_context)

    monkeypatch.setattr(check, "_collect_all_rules", lambda: [])

    result = check.run()

    assert result.passed is False
    assert "-w /etc/netplan/ -p wa -k system-locale" in result.remediation
    assert "-w /etc/NetworkManager/system-connections/ -p wa -k system-locale" in result.remediation
