"""
CIS Audit Check: iptables Installed (3.6.1)

Ensures iptables is installed as an alternative to firewalld.
"""

import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class IPTablesInstalledCheck(BaseCheck):
    """Check if iptables package is installed."""

    id = "iptables_installed"
    name = "iptables Installed"
    description = (
        "Verifies that iptables package is installed as a firewall alternative "
        "to firewalld"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _is_installed(self) -> tuple[bool, str]:
        """Check if iptables package is installed.

        Returns:
            Tuple of (installed, method_used)
        """
        return self.platform_context.check_package_installed("iptables")

    def _check_iptables_binary(self) -> bool:
        """Check if iptables binary exists.

        Returns:
            True if binary exists, False otherwise
        """
        try:
            result = subprocess.run(
                ["which", "iptables"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the iptables installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        installed, method = self._is_installed()
        binary_exists = self._check_iptables_binary()

        details = {
            "installed": installed,
            "installation_method": method,
            "binary_exists": binary_exists,
        }

        if installed or binary_exists:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="iptables is installed on this system",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        install_cmd = self.platform_context.render_remediation(
            "install_packages",
            packages="iptables",
        ) or "sudo dnf install iptables"

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="iptables is not installed on this system",
            remediation=(
                "Install iptables as a firewall alternative:\n"
                f"1. Install iptables: {install_cmd}\n"
                "2. Verify installation: iptables --version\n"
                "3. Configure firewall rules as needed\n"
                "Note: Either firewalld or iptables should be configured, not both"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
