"""
CIS Audit Check: Prelink Not Installed (1.4.3)

Ensures the prelink package is not installed as it can interfere with
ASLR and make exploitation of memory corruption vulnerabilities easier.
"""

import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class PrelinkCheck(BaseCheck):
    """Check that prelink package is not installed."""

    id = "proc_prelink"
    name = "Prelink Not Installed"
    description = (
        "Ensures the prelink package is not installed as it can interfere "
        "with ASLR and make exploitation of memory corruption vulnerabilities easier"
    )
    severity = Severity.MEDIUM
    requires_root = True

    PRELINK_PACKAGE = "prelink"

    def _check_package_installed(self) -> dict:
        """Check if prelink package is installed.

        Returns:
            Dictionary with package check results
        """
        result = {
            "installed": False,
            "package": self.PRELINK_PACKAGE,
            "version": None,
        }

        try:
            rpm_result = subprocess.run(
                ["rpm", "-q", self.PRELINK_PACKAGE],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if rpm_result.returncode == 0:
                result["installed"] = True
                result["version"] = rpm_result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the prelink check.

        Returns:
            CheckResult with the outcome of the check
        """
        package_info = self._check_package_installed()

        details = {
            "package": package_info,
        }

        if not package_info["installed"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Prelink package is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Prelink package is installed ({package_info['version']})",
            remediation=(
                "Remove prelink package to prevent ASLR interference:\n"
                "1. Remove the prelink package:\n"
                "   sudo dnf remove prelink\n"
                "2. Verify removal:\n"
                "   rpm -q prelink\n"
                "\n"
                "Note: Prelink modifies binaries to speed up startup but "
                "interferes with ASLR security features."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
