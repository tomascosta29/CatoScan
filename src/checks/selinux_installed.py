"""
CIS Audit Check: SELinux Installed

Checks if SELinux packages (policycoreutils and selinux-policy) are installed.
CIS 1.5.1.1
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxInstalledCheck(BaseCheck):
    """Check if SELinux packages are installed."""

    id = "selinux_installed"
    name = "SELinux Packages Installed"
    description = (
        "Verifies that SELinux packages (policycoreutils and selinux-policy) "
        "are installed on the system"
    )
    severity = Severity.HIGH
    requires_root = True

    REQUIRED_PACKAGES = [
        "policycoreutils",
        "selinux-policy",
    ]

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed using rpm.

        Args:
            package: Package name to check

        Returns:
            True if package is installed, False otherwise
        """
        try:
            result = subprocess.run(
                ["rpm", "-q", package],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the SELinux packages check.

        Returns:
            CheckResult with the outcome of the check
        """
        missing_packages = []
        installed_packages = []

        for package in self.REQUIRED_PACKAGES:
            if self._check_package_installed(package):
                installed_packages.append(package)
            else:
                missing_packages.append(package)

        if missing_packages:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"SELinux packages not installed: {', '.join(missing_packages)}",
                remediation=(
                    f"Install missing SELinux packages:\n"
                    f"dnf install {' '.join(missing_packages)}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "missing_packages": missing_packages,
                    "installed_packages": installed_packages,
                    "required_packages": self.REQUIRED_PACKAGES,
                },
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All required SELinux packages are installed: {', '.join(installed_packages)}",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "installed_packages": installed_packages,
                "required_packages": self.REQUIRED_PACKAGES,
            },
        )
