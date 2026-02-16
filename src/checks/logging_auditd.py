"""
CIS Audit Check: auditd Service

Checks if auditd is installed, running, and enabled for system auditing.
"""

import os
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class AuditdCheck(BaseCheck):
    """Check for auditd service installation and configuration."""

    id = "logging_auditd"
    name = "auditd Service Status"
    description = (
        "Verifies that auditd is installed, running, and enabled "
        "to ensure proper system auditing"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _is_installed(self) -> bool:
        """Check if audit package is installed."""
        try:
            result = subprocess.run(
                ["rpm", "-q", "audit"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _is_running(self) -> bool:
        """Check if auditd service is running."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and "active" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _is_enabled(self) -> bool:
        """Check if auditd service is enabled."""
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", "auditd"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and (
                "enabled" in result.stdout or "enabled-runtime" in result.stdout
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the auditd check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "installed": False,
            "running": False,
            "enabled": False,
        }

        # Check if auditd is installed
        details["installed"] = self._is_installed()

        if not details["installed"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="audit package is not installed",
                remediation=(
                    "Install audit to ensure proper system auditing:\n"
                    "1. Install audit: dnf install audit\n"
                    "2. Enable the service: systemctl enable auditd\n"
                    "3. Start the service: systemctl start auditd\n"
                    "4. Verify status: systemctl status auditd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if auditd is running
        details["running"] = self._is_running()

        # Check if auditd is enabled
        details["enabled"] = self._is_enabled()

        # Determine overall status
        if not details["running"] and not details["enabled"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="auditd is installed but not running and not enabled",
                remediation=(
                    "Enable and start auditd service:\n"
                    "1. Enable the service: systemctl enable auditd\n"
                    "2. Start the service: systemctl start auditd\n"
                    "3. Verify status: systemctl status auditd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not details["running"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="auditd is installed and enabled but not currently running",
                remediation=(
                    "Start the auditd service:\n"
                    "1. Start the service: systemctl start auditd\n"
                    "2. Check for errors: journalctl -u auditd -n 50\n"
                    "3. Check auditd configuration in /etc/audit/auditd.conf"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not details["enabled"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="auditd is installed and running but not enabled (won't start on boot)",
                remediation=(
                    "Enable auditd to start on boot:\n"
                    "1. Enable the service: systemctl enable auditd\n"
                    "2. Verify: systemctl is-enabled auditd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="auditd is installed, running, and enabled",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
