"""
CIS Audit Check: AppArmor Installed (1.5.2)

Checks if AppArmor packages are installed.
Note: This check is optional for Fedora as Fedora uses SELinux instead of AppArmor.
This check is primarily for Debian/Ubuntu-based distributions.
CIS 1.5.2
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxAppArmorInstalledCheck(BaseCheck):
    """Check if AppArmor packages are installed.
    
    Note: This check is marked as optional because Fedora uses SELinux
    instead of AppArmor. This check is primarily relevant for
    Debian/Ubuntu-based distributions.
    """

    id = "selinux_apparmor_installed"
    name = "AppArmor Installed"
    description = (
        "Verifies that AppArmor packages are installed. "
        "Note: Fedora uses SELinux instead of AppArmor. "
        "This check is optional for Fedora systems."
    )
    severity = Severity.HIGH
    requires_root = True
    optional = True  # Fedora uses SELinux, not AppArmor

    REQUIRED_PACKAGES = [
        "apparmor",
        "apparmor-utils",
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

    def _check_selinux_installed(self) -> bool:
        """Check if SELinux is installed (Fedora's MAC system).

        Returns:
            True if SELinux packages are installed
        """
        try:
            result = subprocess.run(
                ["rpm", "-q", "selinux-policy"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the AppArmor check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if SELinux is installed (Fedora uses SELinux)
        selinux_installed = self._check_selinux_installed()

        # Check for AppArmor packages
        apparmor_packages = []
        for package in self.REQUIRED_PACKAGES:
            if self._check_package_installed(package):
                apparmor_packages.append(package)

        # If SELinux is installed, this is a Fedora system and AppArmor is not needed
        if selinux_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SELinux is installed - AppArmor not required on Fedora",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "selinux_installed": True,
                    "apparmor_packages": apparmor_packages,
                    "note": "Fedora uses SELinux instead of AppArmor",
                },
            )

        # Check if AppArmor is installed (for non-Fedora systems)
        if apparmor_packages:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"AppArmor packages installed: {', '.join(apparmor_packages)}",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "selinux_installed": False,
                    "apparmor_packages": apparmor_packages,
                    "required_packages": self.REQUIRED_PACKAGES,
                },
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="AppArmor packages are not installed",
            remediation=(
                "Install AppArmor packages:\n"
                "dnf install apparmor apparmor-utils\n\n"
                "Note: Fedora uses SELinux by default. "
                "This check is primarily for Debian/Ubuntu systems."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "selinux_installed": selinux_installed,
                "apparmor_packages": [],
                "required_packages": self.REQUIRED_PACKAGES,
            },
        )
