"""
CIS Audit Check: SNMP Server Not Installed

Checks if SNMP server is not installed (CIS 2.2.14).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class SNMPServerNotInstalledCheck(BaseCheck):
    """Check if SNMP server is not installed."""

    id = "svc_snmp_server"
    name = "SNMP Server Not Installed"
    description = (
        "Verifies that SNMP server is not installed to prevent "
        "unnecessary network management services"
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
        """Execute the SNMP server not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if net-snmp package is installed
        snmp_installed = self._check_package_installed("net-snmp")

        # Check snmpd service status
        service_status = self._check_service_status("snmpd")

        details = {
            "net_snmp_package_installed": snmp_installed,
            "service_status": service_status,
        }

        # Determine result
        if not snmp_installed and not service_status["installed"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SNMP server is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("net-snmp")
        status_cmd = self._platform_status_service_command("snmpd")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package and service state:\n"
            "   rpm -q net-snmp\n"
            f"   {status_cmd}"
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="SNMP server is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
