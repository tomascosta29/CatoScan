"""
CIS Audit Check: CUPS Not Installed

Checks if CUPS is not installed (CIS 2.2.4).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class CUPSNotInstalledCheck(BaseCheck):
    """Check if CUPS is not installed."""

    id = "svc_cups"
    name = "CUPS Not Installed"
    description = (
        "Verifies that CUPS is not installed to prevent "
        "unnecessary printing services"
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
        return self._platform_package_installed(package)

    def _check_service_status(self, service: str) -> dict:
        """Check if a service is installed and running.

        Args:
            service: Name of the service to check

        Returns:
            Dictionary with service status information
        """
        return self._platform_service_status(service)

    def run(self) -> CheckResult:
        """Execute the CUPS not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if cups package is installed
        cups_installed = self._check_package_installed("cups")

        # Check cups service status
        service_status = self._check_service_status("cups")

        details = {
            "cups_package_installed": cups_installed,
            "service_status": service_status,
        }

        # Determine result
        if not cups_installed and not service_status["installed"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="CUPS is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("cups")
        status_cmd = self._platform_status_service_command("cups")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package and service state:\n"
            "   rpm -q cups\n"
            f"   {status_cmd}"
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="CUPS is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
