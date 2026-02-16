"""
CIS Audit Check: talk Client Not Installed

Checks if talk client is not installed (CIS 2.3.3).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class TalkClientNotInstalledCheck(BaseCheck):
    """Check if talk client is not installed."""

    id = "svc_talk_client"
    name = "talk Client Not Installed"
    description = (
        "Verifies that talk client is not installed to prevent "
        "unauthorized user communication"
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
        """Execute the talk client not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if talk package is installed
        talk_installed = self._check_package_installed("talk")

        details = {
            "talk_package_installed": talk_installed,
        }

        # Determine result
        if not talk_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="talk client is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("talk")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package is removed:\n"
            "   rpm -q talk\n\n"
            "Note: This package may increase attack surface and is recommended to be removed."
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="talk client is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
