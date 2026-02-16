"""
CIS Audit Check: LDAP Client Not Installed

Checks if LDAP client is not installed (CIS 2.3.5).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class LDAPClientNotInstalledCheck(BaseCheck):
    """Check if LDAP client is not installed."""

    id = "svc_ldap_client"
    name = "LDAP Client Not Installed"
    description = (
        "Verifies that LDAP client is not installed unless required "
        "for authentication"
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
        """Execute the LDAP client not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if openldap-clients package is installed
        openldap_clients_installed = self._check_package_installed("openldap-clients")

        details = {
            "openldap_clients_package_installed": openldap_clients_installed,
        }

        # Determine result
        if not openldap_clients_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="LDAP client is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("openldap-clients")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package is removed:\n"
            "   rpm -q openldap-clients\n\n"
            "Note: This package may increase attack surface and is recommended to be removed."
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="LDAP client is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
