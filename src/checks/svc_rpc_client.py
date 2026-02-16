"""
CIS Audit Check: RPC Client Not Installed

Checks if RPC client is not installed (CIS 2.3.6).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class RPCClientNotInstalledCheck(BaseCheck):
    """Check if RPC client is not installed."""

    id = "svc_rpc_client"
    name = "RPC Client Not Installed"
    description = (
        "Verifies that RPC client is not installed to prevent "
        "unnecessary network services"
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
        """Execute the RPC client not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if rpcbind package is installed
        rpcbind_installed = self._check_package_installed("rpcbind")

        details = {
            "rpcbind_package_installed": rpcbind_installed,
        }

        # Determine result
        if not rpcbind_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="RPC client is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("rpcbind")

        remediation = (
            "Remove package:\n\n"
            "1. Remove package:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify package is removed:\n"
            "   rpm -q rpcbind\n\n"
            "Note: This package may increase attack surface and is recommended to be removed."
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="RPC client is installed",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
