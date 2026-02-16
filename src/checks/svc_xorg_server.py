"""
CIS Audit Check: Xorg X11 Server Not Installed (2.2.2)

Ensures that xorg-x11-server-common is not installed for server hardening.
This check is marked as optional because it's only applicable for servers,
not desktop systems that require X11 for graphical interface.
CIS 2.2.2
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class XorgServerNotInstalledCheck(BaseCheck):
    """Check if Xorg X11 server is not installed for server hardening.
    
    Note: This check is marked as optional because it's only applicable
    for server environments. Desktop systems require X11 for graphical
    user interface.
    """

    id = "svc_xorg_server"
    name = "Xorg X11 Server Not Installed"
    description = (
        "Verifies that xorg-x11-server-common is not installed. "
        "This is recommended for server hardening. "
        "Note: This check is optional as it's not applicable for desktop systems."
    )
    severity = Severity.MEDIUM
    requires_root = True
    optional = True  # Only applicable for servers, not desktops

    XORG_PACKAGES = [
        "xorg-x11-server-common",
        "xorg-x11-server-Xorg",
        "xorg-x11-server-utils",
    ]

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed using rpm.

        Args:
            package: Package name to check

        Returns:
            True if package is installed, False otherwise
        """
        return self._platform_package_installed(package)

    def _check_x11_running(self) -> bool:
        """Check if X11 server is currently running.

        Returns:
            True if X11 is running
        """
        try:
            # Check for X11 display
            result = subprocess.run(
                ["pgrep", "-x", "Xorg"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True

            # Alternative: check for any X server
            result = subprocess.run(
                ["pgrep", "-x", "X"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the Xorg server check.

        Returns:
            CheckResult with the outcome of the check
        """
        installed_packages = []
        for package in self.XORG_PACKAGES:
            if self._check_package_installed(package):
                installed_packages.append(package)

        x11_running = self._check_x11_running()

        details = {
            "installed_packages": installed_packages,
            "x11_running": x11_running,
        }

        if not installed_packages:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Xorg X11 server packages are not installed - server hardening satisfied",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Xorg is installed
        if x11_running:
            remove_cmd = self._platform_remove_packages_command(" ".join(installed_packages))
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Xorg X11 server is installed and running. "
                    f"Installed packages: {', '.join(installed_packages)}"
                ),
                remediation=(
                    "For server hardening, remove Xorg X11 server:\n"
                    f"{remove_cmd}\n\n"
                    "Note: Only remove Xorg on server systems. "
                    "Desktop systems require X11 for graphical interface."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Xorg is installed but not running
        remove_cmd = self._platform_remove_packages_command(" ".join(installed_packages))
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"Xorg X11 server is installed but not running. "
                f"Installed packages: {', '.join(installed_packages)}"
            ),
            remediation=(
                "For server hardening, remove Xorg X11 server:\n"
                f"{remove_cmd}\n\n"
                "Note: Only remove Xorg on server systems. "
                "Desktop systems require X11 for graphical interface."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
