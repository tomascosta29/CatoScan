"""
CIS Audit Check: mcstrans Not Installed

Checks that mcstrans (Multi-Category Security Translation Service) is not installed.
CIS 1.5.1.7
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxMcstransCheck(BaseCheck):
    """Check that mcstrans is not installed."""

    id = "selinux_mcstrans"
    name = "mcstrans Not Installed"
    description = (
        "Verifies that mcstrans (Multi-Category Security Translation Service) "
        "is not installed, as it is not required for most systems"
    )
    severity = Severity.HIGH
    requires_root = True

    PACKAGES_TO_CHECK = [
        "mcstrans",
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
        """Check if mcstransd service is running.

        Returns:
            Tuple of (is_running, details)
        """
        details = {"methods_tried": []}

        # Check with systemctl
        try:
            details["methods_tried"].append("systemctl")
            result = subprocess.run(
                ["systemctl", "is-active", "mcstransd"],
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
                ["pgrep", "-c", "mcstransd"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip() != "0":
                return True, details
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["ps_error"] = str(e)

        return False, details

    def run(self) -> CheckResult:
        """Execute the mcstrans check.

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
                message=f"mcstrans package is installed: {', '.join(installed_packages)}",
                remediation=(
                    "Remove mcstrans package:\n"
                    "dnf remove mcstrans\n\n"
                    "Note: mcstrans (Multi-Category Security Translation Service) "
                    "translates SELinux MCS/MLS labels to human-readable form. "
                    "It is not required for most systems and should be removed "
                    "unless specifically needed for MLS policy environments."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if is_running:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="mcstransd daemon is running (though package may not be installed via rpm)",
                remediation=(
                    "Stop and disable mcstrans service:\n"
                    "systemctl stop mcstransd\n"
                    "systemctl disable mcstransd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="mcstrans is not installed or running",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
