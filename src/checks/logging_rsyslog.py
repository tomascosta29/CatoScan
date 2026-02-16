"""
CIS Audit Check: rsyslog Service

Checks if rsyslog is installed, running, and enabled for system logging.
"""

import os
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class RsyslogCheck(BaseCheck):
    """Check for rsyslog service installation and configuration."""

    id = "logging_rsyslog"
    name = "rsyslog Service Status"
    description = (
        "Verifies that rsyslog is installed, running, and enabled "
        "to ensure proper system logging"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _is_installed(self) -> bool:
        """Check if rsyslog package is installed."""
        try:
            result = subprocess.run(
                ["rpm", "-q", "rsyslog"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _is_running(self) -> bool:
        """Check if rsyslog service is running."""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "rsyslog"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and "active" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _is_enabled(self) -> bool:
        """Check if rsyslog service is enabled."""
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", "rsyslog"],
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
        """Execute the rsyslog check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "installed": False,
            "running": False,
            "enabled": False,
        }

        # Check if rsyslog is installed
        details["installed"] = self._is_installed()

        if not details["installed"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="rsyslog package is not installed",
                remediation=(
                    "Install rsyslog to ensure proper system logging:\n"
                    "1. Install rsyslog: dnf install rsyslog\n"
                    "2. Enable the service: systemctl enable rsyslog\n"
                    "3. Start the service: systemctl start rsyslog\n"
                    "4. Verify status: systemctl status rsyslog"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if rsyslog is running
        details["running"] = self._is_running()

        # Check if rsyslog is enabled
        details["enabled"] = self._is_enabled()

        # Determine overall status
        if not details["running"] and not details["enabled"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="rsyslog is installed but not running and not enabled",
                remediation=(
                    "Enable and start rsyslog service:\n"
                    "1. Enable the service: systemctl enable rsyslog\n"
                    "2. Start the service: systemctl start rsyslog\n"
                    "3. Verify status: systemctl status rsyslog"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not details["running"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="rsyslog is installed and enabled but not currently running",
                remediation=(
                    "Start the rsyslog service:\n"
                    "1. Start the service: systemctl start rsyslog\n"
                    "2. Check for errors: journalctl -u rsyslog -n 50\n"
                    "3. Verify configuration: rsyslogd -N1"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not details["enabled"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="rsyslog is installed and running but not enabled (won't start on boot)",
                remediation=(
                    "Enable rsyslog to start on boot:\n"
                    "1. Enable the service: systemctl enable rsyslog\n"
                    "2. Verify: systemctl is-enabled rsyslog"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="rsyslog is installed, running, and enabled",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
