"""
CIS Audit Check: rsh Client Not Installed

Checks if rsh client is not installed (CIS 2.3.2).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class RshClientNotInstalledCheck(BaseCheck):
    """Check if rsh client is not installed."""

    id = "svc_rsh_client"
    name = "rsh Client Not Installed"
    description = (
        "Verifies that rsh client is not installed to prevent "
        "insecure remote shell access"
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
        """Execute the rsh client not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if rsh package is installed
        rsh_installed = self._check_package_installed("rsh")

        details = {
            "rsh_package_installed": rsh_installed,
        }

        # Determine result
        if not rsh_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="rsh client is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("rsh")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package is removed:\n"
            "   rpm -q rsh\n\n"
            "Note: This package may increase attack surface and is recommended to be removed."
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="rsh client is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
