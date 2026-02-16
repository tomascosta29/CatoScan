"""
CIS Audit Check: Cron Daemon Enabled (4.1.1)

Ensures that the cron daemon is installed, running, and enabled.
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class CronDaemonCheck(BaseCheck):
    """Check if cron daemon is enabled and running."""

    id = "cron_daemon"
    name = "Cron Daemon Enabled"
    description = (
        "Verifies that the cron daemon (crond) is installed, "
        "running, and enabled"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SERVICE_NAMES = ["crond", "cron"]

    def _check_service_status(self) -> dict:
        """Check if cron service is installed and running.

        Returns:
            Dictionary with service status information
        """
        result = {
            "installed": False,
            "active": False,
            "enabled": False,
            "service_name": None,
        }

        for service in self.SERVICE_NAMES:
            # Check if service is active
            try:
                status_result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if status_result.returncode == 0:
                    result["active"] = True
                    result["installed"] = True
                    result["service_name"] = service
                    break
                elif "could not be found" not in status_result.stderr:
                    result["installed"] = True
                    result["service_name"] = service
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Check if service is enabled (only for found service)
        if result["service_name"]:
            try:
                enabled_result = subprocess.run(
                    ["systemctl", "is-enabled", result["service_name"]],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                result["enabled"] = enabled_result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the cron daemon check.

        Returns:
            CheckResult with the outcome of the check
        """
        service_status = self._check_service_status()

        details = {
            "service": service_status,
        }

        if service_status["active"] and service_status["enabled"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cron daemon ({service_status['service_name']}) is running and enabled",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not service_status["installed"]:
            issues.append("cron daemon is not installed")
        elif not service_status["active"]:
            issues.append(f"cron daemon ({service_status['service_name']}) is not running")
        elif not service_status["enabled"]:
            issues.append(f"cron daemon ({service_status['service_name']}) is not enabled")

        # Build remediation
        remediation_parts = [
            "Ensure cron daemon is installed, running, and enabled:",
            "",
            "1. Install cronie package:",
            "   sudo dnf install cronie",
            "",
            "2. Enable and start the cron service:",
            "   sudo systemctl enable crond",
            "   sudo systemctl start crond",
            "",
            "3. Verify the service is running:",
            "   sudo systemctl status crond",
            "",
            "CIS Benchmark: 4.1.1 - Ensure cron daemon is enabled and running",
        ]

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
