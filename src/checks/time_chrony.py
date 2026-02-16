"""
CIS Audit Check: Chrony Configured

Checks if chrony is installed, running, enabled, and properly configured (CIS 2.1.2).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class ChronyConfiguredCheck(BaseCheck):
    """Check if chrony is properly configured."""

    id = "time_chrony"
    name = "Chrony Configured"
    description = (
        "Verifies that chrony is installed, running, enabled, "
        "and has valid NTP server configuration"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Configuration
    PACKAGE_NAME = "chrony"
    SERVICE_NAME = "chronyd"
    CONFIG_PATH = "/etc/chrony.conf"

    def _check_package_installed(self) -> bool:
        """Check if chrony package is installed.

        Returns:
            True if package is installed, False otherwise
        """
        try:
            result = subprocess.run(
                ["rpm", "-q", self.PACKAGE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _check_service_status(self) -> dict:
        """Check if chrony service is installed and running.

        Returns:
            Dictionary with service status information
        """
        result = {
            "installed": False,
            "active": False,
            "enabled": False,
        }

        # Check if service is active
        try:
            status_result = subprocess.run(
                ["systemctl", "is-active", self.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            result["active"] = status_result.returncode == 0
            result["installed"] = "could not be found" not in status_result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Check if service is enabled
        try:
            enabled_result = subprocess.run(
                ["systemctl", "is-enabled", self.SERVICE_NAME],
                capture_output=True,
                text=True,
                timeout=5,
            )
            result["enabled"] = enabled_result.returncode == 0
            result["installed"] = result["installed"] or "could not be found" not in enabled_result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result

    def _check_config_file(self) -> dict:
        """Check chrony configuration file.

        Returns:
            Dictionary with configuration file status
        """
        result = {
            "config_exists": False,
            "config_path": self.CONFIG_PATH,
            "has_server_config": False,
            "servers": [],
            "pools": [],
        }

        config_file = Path(self.CONFIG_PATH)
        if config_file.exists():
            result["config_exists"] = True
            try:
                with open(config_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("server "):
                            parts = line.split()
                            if len(parts) >= 2:
                                result["servers"].append(parts[1])
                                result["has_server_config"] = True
                        elif line.startswith("pool "):
                            parts = line.split()
                            if len(parts) >= 2:
                                result["pools"].append(parts[1])
                                result["has_server_config"] = True
            except (PermissionError, OSError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the chrony configured check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if chrony is installed
        installed = self._check_package_installed()

        # Check service status
        service_status = self._check_service_status()

        # Check configuration file
        config = self._check_config_file()

        details = {
            "installed": installed,
            "service": service_status,
            "config": config,
        }

        # Determine result
        if installed and service_status["active"] and service_status["enabled"] and config["has_server_config"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="chrony is installed, running, enabled, and has valid NTP server configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not installed:
            issues.append("chrony package is not installed")
        elif not service_status["active"]:
            issues.append("chronyd service is not running")
        elif not service_status["enabled"]:
            issues.append("chronyd service is not enabled")
        elif not config["has_server_config"]:
            issues.append("chrony configuration has no valid server or pool entries")

        # Build remediation
        remediation_parts = [
            "Configure chrony for time synchronization:",
            "",
            "1. Install chrony:",
            f"   sudo dnf install {self.PACKAGE_NAME}",
            "",
            "2. Enable and start the service:",
            f"   sudo systemctl enable {self.SERVICE_NAME}",
            f"   sudo systemctl start {self.SERVICE_NAME}",
            "",
            "3. Configure NTP servers in /etc/chrony.conf:",
            "   # Add or uncomment server lines, for example:",
            "   server 0.fedora.pool.ntp.org iburst",
            "   server 1.fedora.pool.ntp.org iburst",
            "   server 2.fedora.pool.ntp.org iburst",
            "   server 3.fedora.pool.ntp.org iburst",
            "",
            "   # Or use pool directive:",
            "   pool 2.fedora.pool.ntp.org iburst",
            "",
            "4. Restart chronyd after configuration changes:",
            f"   sudo systemctl restart {self.SERVICE_NAME}",
            "",
            "5. Verify configuration:",
            "   chronyc sources",
            "   chronyc tracking",
            "   timedatectl status",
        ]

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
