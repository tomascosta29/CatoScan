"""
CIS Audit Check: GDM Removed (1.7.1)

Ensures that GNOME Display Manager (GDM) is removed for server hardening.
This check is marked as optional because it's only applicable for servers,
not desktop systems.
CIS 1.7.1
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class GDMRemovedCheck(BaseCheck):
    """Check if GDM is removed for server hardening.
    
    Note: This check is marked as optional because it's only applicable
    for server environments. Desktop systems require GDM or another
    display manager for graphical login.
    """

    id = "gdm_removed"
    name = "GDM Removed for Server Hardening"
    description = (
        "Verifies that GNOME Display Manager (GDM) is not installed. "
        "This is recommended for server hardening. "
        "Note: This check is optional as it's not applicable for desktop systems."
    )
    severity = Severity.MEDIUM
    requires_root = True
    optional = True  # Only applicable for servers, not desktops

    GDM_PACKAGES = [
        "gdm",
        "gdm-libs",
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

    def _check_display_manager_running(self) -> bool:
        """Check if any display manager is currently running.

        Returns:
            True if a display manager service is active
        """
        display_managers = ["gdm", "sddm", "lightdm", "xdm"]
        for dm in display_managers:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", dm],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return True
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        return False

    def run(self) -> CheckResult:
        """Execute the GDM removal check.

        Returns:
            CheckResult with the outcome of the check
        """
        installed_packages = []
        for package in self.GDM_PACKAGES:
            if self._check_package_installed(package):
                installed_packages.append(package)

        dm_running = self._check_display_manager_running()

        details = {
            "installed_packages": installed_packages,
            "display_manager_running": dm_running,
        }

        if not installed_packages:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="GDM is not installed - server hardening satisfied",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # GDM is installed - check if it's running
        if dm_running:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"GDM is installed and running. "
                    f"Installed packages: {', '.join(installed_packages)}"
                ),
                remediation=(
                    "For server hardening, remove GDM:\n"
                    f"sudo dnf remove {' '.join(installed_packages)}\n\n"
                    "Note: Only remove GDM on server systems. "
                    "Desktop systems require a display manager."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # GDM is installed but not running
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"GDM is installed but not running. "
                f"Installed packages: {', '.join(installed_packages)}"
            ),
            remediation=(
                "For server hardening, remove GDM:\n"
                f"sudo dnf remove {' '.join(installed_packages)}\n\n"
                "Note: Only remove GDM on server systems. "
                "Desktop systems require a display manager."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
