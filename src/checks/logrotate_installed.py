"""
CIS Audit Check: Logrotate Installed (4.3.1)

Ensures that logrotate is installed to manage log file rotation
and prevent disk space issues.
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class LogrotateInstalledCheck(BaseCheck):
    """Check if logrotate is installed."""

    id = "logrotate_installed"
    name = "Logrotate Installed"
    description = (
        "Verifies that logrotate is installed to manage log file rotation"
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

    def _check_logrotate_binary(self) -> bool:
        """Check if logrotate binary exists.

        Returns:
            True if binary exists
        """
        common_paths = [
            "/usr/sbin/logrotate",
            "/usr/bin/logrotate",
            "/sbin/logrotate",
            "/bin/logrotate",
        ]
        for path in common_paths:
            if Path(path).exists():
                return True
        return False

    def run(self) -> CheckResult:
        """Execute the logrotate installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        package_installed = self._check_package_installed("logrotate")
        binary_exists = self._check_logrotate_binary()

        details = {
            "package_installed": package_installed,
            "binary_exists": binary_exists,
        }

        if package_installed or binary_exists:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="logrotate is installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="logrotate is not installed",
            remediation=(
                "Install logrotate:\n\n"
                "  sudo dnf install logrotate\n\n"
                "After installation, configure logrotate in /etc/logrotate.conf\n\n"
                "CIS Benchmark: 4.3.1 - Ensure logrotate is installed"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
