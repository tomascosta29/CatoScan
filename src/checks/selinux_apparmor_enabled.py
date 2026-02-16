"""
CIS Audit Check: AppArmor Enabled (1.5.3)

Checks if AppArmor is enabled and running.
Note: This check is optional for Fedora as Fedora uses SELinux instead of AppArmor.
This check is primarily for Debian/Ubuntu-based distributions.
CIS 1.5.3
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxAppArmorEnabledCheck(BaseCheck):
    """Check if AppArmor is enabled and running.
    
    Note: This check is marked as optional because Fedora uses SELinux
    instead of AppArmor. This check is primarily relevant for
    Debian/Ubuntu-based distributions.
    """

    id = "selinux_apparmor_enabled"
    name = "AppArmor Enabled"
    description = (
        "Verifies that AppArmor is enabled and running. "
        "Note: Fedora uses SELinux instead of AppArmor. "
        "This check is optional for Fedora systems."
    )
    severity = Severity.HIGH
    requires_root = True
    optional = True  # Fedora uses SELinux, not AppArmor

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

    def _check_apparmor_status(self) -> dict:
        """Check AppArmor status using aa-status command.

        Returns:
            Dictionary with AppArmor status information
        """
        result = {
            "aa_status_available": False,
            "apparmor_enabled": False,
            "profiles_loaded": 0,
            "profiles_enforced": 0,
            "profiles_complain": 0,
            "raw_output": "",
        }

        try:
            proc = subprocess.run(
                ["aa-status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            result["aa_status_available"] = True
            result["raw_output"] = proc.stdout

            if proc.returncode == 0:
                # Parse aa-status output
                for line in proc.stdout.split("\n"):
                    if "apparmor module is loaded" in line.lower():
                        result["apparmor_enabled"] = True
                    elif "profiles are loaded" in line.lower():
                        try:
                            result["profiles_loaded"] = int(
                                line.split()[0]
                            )
                        except (ValueError, IndexError):
                            pass
                    elif "profiles are in enforce mode" in line.lower():
                        try:
                            result["profiles_enforced"] = int(
                                line.split()[0]
                            )
                        except (ValueError, IndexError):
                            pass
                    elif "profiles are in complain mode" in line.lower():
                        try:
                            result["profiles_complain"] = int(
                                line.split()[0]
                            )
                        except (ValueError, IndexError):
                            pass

        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return result

    def _check_apparmor_service(self) -> bool:
        """Check if AppArmor service is enabled.

        Returns:
            True if AppArmor service is enabled
        """
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", "apparmor"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run(self) -> CheckResult:
        """Execute the AppArmor enabled check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if SELinux is installed (Fedora uses SELinux)
        selinux_installed = self._check_selinux_installed()

        if selinux_installed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SELinux is installed - AppArmor not required on Fedora",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "selinux_installed": True,
                    "note": "Fedora uses SELinux instead of AppArmor",
                },
            )

        # Check AppArmor status
        apparmor_status = self._check_apparmor_status()
        service_enabled = self._check_apparmor_service()

        details = {
            "selinux_installed": selinux_installed,
            "apparmor_status": apparmor_status,
            "service_enabled": service_enabled,
        }

        # Check if AppArmor is properly enabled
        if apparmor_status["apparmor_enabled"] and service_enabled:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"AppArmor is enabled with {apparmor_status['profiles_enforced']} "
                    f"enforced profiles and {apparmor_status['profiles_loaded']} loaded profiles"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if apparmor_status["apparmor_enabled"] and not service_enabled:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="AppArmor is loaded but service is not enabled",
                remediation=(
                    "Enable AppArmor service:\n"
                    "sudo systemctl enable apparmor\n"
                    "sudo systemctl start apparmor"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if service_enabled and not apparmor_status["apparmor_enabled"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="AppArmor service is enabled but module is not loaded",
                remediation=(
                    "Load AppArmor module:\n"
                    "sudo modprobe apparmor\n\n"
                    "If AppArmor is not installed, install it:\n"
                    "sudo dnf install apparmor"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="AppArmor is not enabled",
            remediation=(
                "Enable AppArmor:\n"
                "sudo systemctl enable apparmor\n"
                "sudo systemctl start apparmor\n\n"
                "If AppArmor is not installed:\n"
                "sudo dnf install apparmor apparmor-utils"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
