"""
CIS Audit Check: Avahi Not Installed

Checks if Avahi is not installed (CIS 2.2.3).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class AvahiNotInstalledCheck(BaseCheck):
    """Check if Avahi is not installed."""

    id = "svc_avahi"
    name = "Avahi Not Installed"
    description = (
        "Verifies that Avahi is not installed to prevent "
        "automatic network service discovery"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed using rpm.

        Args:
            package: Name of the package to check

        Returns:
            True if package is installed, False otherwise
        """
        installed, _ = self.platform_context.check_package_installed(package)
        return installed

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

        active, active_status = self.platform_context.check_service_active(service)
        enabled, enabled_status = self.platform_context.check_service_enabled(service)

        result["active"] = active
        result["enabled"] = enabled

        status_text = f"{active_status} {enabled_status}".lower()
        not_found_markers = ["could not be found", "not-found", "not found", "no such file"]
        result["installed"] = not any(marker in status_text for marker in not_found_markers)

        return result

    def run(self) -> CheckResult:
        """Execute the Avahi not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if avahi package is installed
        avahi_installed = self._check_package_installed("avahi")

        # Check avahi service status
        service_status = self._check_service_status("avahi-daemon")

        details = {
            "avahi_package_installed": avahi_installed,
            "service_status": service_status,
        }

        # Determine result
        if not avahi_installed and not service_status["installed"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Avahi is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("avahi")
        status_cmd = self._platform_status_service_command("avahi-daemon")

        remediation = (
            "Remove Avahi package:\n\n"
            "1. Remove Avahi:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify Avahi is removed:\n"
            "   rpm -q avahi\n"
            f"   {status_cmd}"
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="Avahi is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
