"""
CIS Audit Check: telnet Client Not Installed

Checks if telnet client is not installed (CIS 2.3.4).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class TelnetClientNotInstalledCheck(BaseCheck):
    """Check if telnet client is not installed."""

    id = "svc_telnet_client"
    name = "telnet Client Not Installed"
    description = (
        "Verifies that telnet client is not installed to prevent "
        "insecure remote connections"
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

    def run(self) -> CheckResult:
        """Execute the telnet client not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if telnet package is installed
        telnet_installed = self._check_package_installed("telnet")

        details = {
            "telnet_package_installed": telnet_installed,
        }

        # Determine result
        if not telnet_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="telnet client is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("telnet")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package is removed:\n"
            "   rpm -q telnet\n\n"
            "Note: This package may increase attack surface and is recommended to be removed."
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="telnet client is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
