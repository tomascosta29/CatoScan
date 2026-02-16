"""
CIS Audit Check: SETroubleshoot Not Installed

Checks that SETroubleshoot is not installed on the system.
CIS 1.5.1.6
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxSETroubleshootCheck(BaseCheck):
    """Check that SETroubleshoot is not installed."""

    id = "selinux_setroubleshoot"
    name = "SETroubleshoot Not Installed"
    description = (
        "Verifies that SETroubleshoot is not installed, as it can "
        "leak sensitive information through error messages"
    )
    severity = Severity.HIGH
    requires_root = True

    PACKAGES_TO_CHECK = [
        "setroubleshoot",
        "setroubleshoot-server",
        "setroubleshoot-plugins",
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

    def _check_service_running(self) -> tuple[bool, dict]:
        """Check if setroubleshootd service is running.

        Returns:
            Tuple of (is_running, details)
        """
        details = {"methods_tried": []}

        # Check with systemctl
        try:
            details["methods_tried"].append("systemctl")
            result = subprocess.run(
                ["systemctl", "is-active", "setroubleshootd"],
                capture_output=True,
                text=True,
            )
            details["systemctl_status"] = result.stdout.strip()
            if result.returncode == 0:
                return True, details
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["systemctl_error"] = str(e)

        # Check with ps
        try:
            details["methods_tried"].append("ps")
            result = subprocess.run(
                ["pgrep", "-c", "setroubleshootd"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip() != "0":
                return True, details
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["ps_error"] = str(e)

        return False, details

    def run(self) -> CheckResult:
        """Execute the SETroubleshoot check.

        Returns:
            CheckResult with the outcome of the check
        """
        installed_packages = []

        for package in self.PACKAGES_TO_CHECK:
            if self._check_package_installed(package):
                installed_packages.append(package)

        is_running, service_details = self._check_service_running()

        details = {
            "installed_packages": installed_packages,
            "service_check": service_details,
        }

        if installed_packages:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"SETroubleshoot packages are installed: {', '.join(installed_packages)}",
                remediation=(
                    "Remove SETroubleshoot packages:\n"
                    f"dnf remove {' '.join(installed_packages)}\n\n"
                    "Note: SETroubleshoot can leak sensitive information through "
                    "user notifications. Use ausearch and audit logs instead to "
                    "troubleshoot SELinux denials."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if is_running:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="SETroubleshoot daemon is running (though packages may not be installed via rpm)",
                remediation=(
                    "Stop and disable SETroubleshoot service:\n"
                    "systemctl stop setroubleshootd\n"
                    "systemctl disable setroubleshootd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="SETroubleshoot is not installed or running",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
