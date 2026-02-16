"""
CIS Audit Check: systemd-timesyncd Configured

Checks if systemd-timesyncd is installed, running, enabled, and properly configured (CIS 2.1.3).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class TimesyncdConfiguredCheck(BaseCheck):
    """Check if systemd-timesyncd is properly configured."""

    id = "time_timesyncd"
    name = "systemd-timesyncd Configured"
    description = (
        "Verifies that systemd-timesyncd is installed, running, enabled, "
        "and has valid NTP server configuration"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Configuration
    PACKAGE_NAME = "systemd-timesyncd"
    SERVICE_NAME = "systemd-timesyncd"
    CONFIG_PATH = "/etc/systemd/timesyncd.conf"

    def _check_package_installed(self) -> bool:
        """Check if systemd-timesyncd package is installed.

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
        """Check if systemd-timesyncd service is installed and running.

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
        """Check systemd-timesyncd configuration file.

        Returns:
            Dictionary with configuration file status
        """
        result = {
            "config_exists": False,
            "config_path": self.CONFIG_PATH,
            "has_ntp_config": False,
            "ntp_servers": [],
            "fallback_ntp": [],
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
                        if line.startswith("NTP="):
                            servers = line[4:].strip()
                            if servers:
                                result["ntp_servers"] = [s.strip() for s in servers.split()]
                                result["has_ntp_config"] = True
                        elif line.startswith("FallbackNTP="):
                            servers = line[12:].strip()
                            if servers:
                                result["fallback_ntp"] = [s.strip() for s in servers.split()]
            except (PermissionError, OSError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the systemd-timesyncd configured check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if systemd-timesyncd is installed
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
        if installed and service_status["active"] and service_status["enabled"] and config["has_ntp_config"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="systemd-timesyncd is installed, running, enabled, and has valid NTP server configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not installed:
            issues.append("systemd-timesyncd package is not installed")
        elif not service_status["active"]:
            issues.append("systemd-timesyncd service is not running")
        elif not service_status["enabled"]:
            issues.append("systemd-timesyncd service is not enabled")
        elif not config["has_ntp_config"]:
            issues.append("systemd-timesyncd configuration has no valid NTP server entries")

        # Build remediation
        remediation_parts = [
            "Configure systemd-timesyncd for time synchronization:",
            "",
            "1. Install systemd-timesyncd:",
            f"   sudo dnf install {self.PACKAGE_NAME}",
            "",
            "2. Enable and start the service:",
            f"   sudo systemctl enable {self.SERVICE_NAME}",
            f"   sudo systemctl start {self.SERVICE_NAME}",
            "",
            "3. Configure NTP servers in /etc/systemd/timesyncd.conf:",
            "   Edit the [Time] section and add:",
            "   NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org 2.fedora.pool.ntp.org 3.fedora.pool.ntp.org",
            "   FallbackNTP=time.google.com time.cloudflare.com",
            "",
            "4. Restart systemd-timesyncd after configuration changes:",
            f"   sudo systemctl restart {self.SERVICE_NAME}",
            "",
            "5. Verify configuration:",
            "   timedatectl status",
            "   timedatectl show-timesync",
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
