"""
CIS Audit Check: Automounting Disabled

Checks if automounting is disabled (CIS 1.1.21).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AutomountDisabledCheck(BaseCheck):
    """Check if automounting is disabled."""

    id = "fs_automount"
    name = "Automounting Disabled"
    description = (
        "Verifies that automounting is disabled to prevent "
        "automatic mounting of removable media"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Services that provide automounting functionality
    AUTOMOUNT_SERVICES = [
        "autofs",
        "autofs.service",
        "udisks2",
        "udisks2.service",
    ]

    def _check_service_status(self, service: str) -> dict:
        """Check if a service is installed and running.

        Args:
            service: Name of the service to check

        Returns:
            Dictionary with service status information
        """
        result = {
            "service": service,
            "installed": False,
            "active": False,
            "enabled": False,
        }

        # Check if service is active
        try:
            status_result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True,
                text=True,
                timeout=5,
            )
            result["active"] = status_result.returncode == 0
            result["installed"] = "could not be found" not in status_result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Check if service is enabled
        try:
            enabled_result = subprocess.run(
                ["systemctl", "is-enabled", service],
                capture_output=True,
                text=True,
                timeout=5,
            )
            result["enabled"] = enabled_result.returncode == 0
            result["installed"] = result["installed"] or "could not be found" not in enabled_result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result

    def _check_automount_services(self) -> list[dict]:
        """Check status of all automount-related services.

        Returns:
            List of dictionaries with service status information
        """
        services = []
        for service in self.AUTOMOUNT_SERVICES:
            status = self._check_service_status(service)
            services.append(status)
        return services

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed using rpm.

        Args:
            package: Name of the package to check

        Returns:
            True if package is installed, False otherwise
        """
        try:
            result = subprocess.run(
                ["rpm", "-q", package],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the automounting disabled check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check automount services
        service_statuses = self._check_automount_services()

        # Check if autofs package is installed
        autofs_installed = self._check_package_installed("autofs")

        # Find any active or enabled automount services
        active_services = [
            s for s in service_statuses
            if s["active"] or s["enabled"]
        ]

        details = {
            "service_statuses": service_statuses,
            "autofs_package_installed": autofs_installed,
            "active_or_enabled_services": active_services,
        }

        # Determine result
        if not active_services and not autofs_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Automounting is disabled (autofs not installed, no automount services active)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if autofs_installed:
            issues.append("autofs package is installed")
        if active_services:
            service_names = [s["service"] for s in active_services]
            issues.append(f"automount services active/enabled: {', '.join(service_names)}")

        # Build remediation
        remediation_parts = ["Disable automounting:"]

        if autofs_installed:
            remediation_parts.extend([
                "",
                "1. Remove autofs package:",
                "   sudo dnf remove autofs",
            ])

        for service in active_services:
            svc = service["service"]
            remediation_parts.extend([
                "",
                f"2. Stop and disable {svc}:",
                f"   sudo systemctl stop {svc}",
                f"   sudo systemctl disable {svc}",
            ])

        remediation_parts.extend([
            "",
            "3. Verify automounting is disabled:",
            "   systemctl status autofs",
            "   rpm -q autofs",
        ])

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
