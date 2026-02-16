"""
CIS Audit Check: Time Synchronization Enabled

Checks if a time synchronization service is in use (CIS 2.1.1).
This check verifies that either chrony or systemd-timesyncd is installed,
running, and enabled.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class TimeSyncEnabledCheck(BaseCheck):
    """Check if time synchronization is enabled (chrony or timesyncd)."""

    id = "time_sync_enabled"
    name = "Time Synchronization Enabled"
    description = (
        "Verifies that a time synchronization service (chrony or systemd-timesyncd) "
        "is installed, running, and enabled"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Time sync services to check
    SERVICES = ["chronyd", "chrony", "systemd-timesyncd"]

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed using rpm.

        Args:
            package: Name of the package to check

        Returns:
            True if package is installed, False otherwise
        """
        return self._platform_package_installed(package)

    def _check_service_status(self, service: str) -> dict:
        """Check if a service is installed and running.

        Args:
            service: Name of the service to check

        Returns:
            Dictionary with service status information
        """
        return self._platform_service_status(service)

    def _check_config_file(self, service: str) -> dict:
        """Check configuration file for the time sync service.

        Args:
            service: Name of the service

        Returns:
            Dictionary with configuration file status
        """
        config_paths = {
            "chronyd": "/etc/chrony.conf",
            "chrony": "/etc/chrony.conf",
            "systemd-timesyncd": "/etc/systemd/timesyncd.conf",
        }

        result = {
            "config_exists": False,
            "config_path": None,
            "has_valid_config": False,
        }

        config_path = config_paths.get(service)
        if not config_path:
            return result

        result["config_path"] = config_path
        config_file = Path(config_path)
        if config_file.exists():
            result["config_exists"] = True
            try:
                with open(config_file, "r") as f:
                    content = f.read()
                    # Check for valid configuration
                    if service in ["chronyd", "chrony"]:
                        # Check for server or pool configuration
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#"):
                                if line.startswith("server ") or line.startswith("pool "):
                                    result["has_valid_config"] = True
                                    break
                    elif service == "systemd-timesyncd":
                        # Check for NTP configuration
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#"):
                                if line.startswith("NTP=") and len(line) > 4:
                                    result["has_valid_config"] = True
                                    break
            except (PermissionError, OSError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the time synchronization enabled check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check for chrony
        chrony_installed = self._check_package_installed("chrony")
        chrony_status = self._check_service_status("chronyd")
        chrony_config = self._check_config_file("chronyd")

        # Check for systemd-timesyncd
        timesyncd_installed = self._check_package_installed("systemd-timesyncd")
        timesyncd_status = self._check_service_status("systemd-timesyncd")
        timesyncd_config = self._check_config_file("systemd-timesyncd")

        details = {
            "chrony": {
                "installed": chrony_installed,
                "service": chrony_status,
                "config": chrony_config,
            },
            "timesyncd": {
                "installed": timesyncd_installed,
                "service": timesyncd_status,
                "config": timesyncd_config,
            },
        }

        # Check if either service is properly configured
        chrony_ok = (
            chrony_installed and
            chrony_status["active"] and
            chrony_status["enabled"] and
            chrony_config["has_valid_config"]
        )

        timesyncd_ok = (
            timesyncd_installed and
            timesyncd_status["active"] and
            timesyncd_status["enabled"] and
            timesyncd_config["has_valid_config"]
        )

        if chrony_ok or timesyncd_ok:
            service_name = "chrony" if chrony_ok else "systemd-timesyncd"
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Time synchronization is enabled using {service_name}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not chrony_installed and not timesyncd_installed:
            issues.append("Neither chrony nor systemd-timesyncd is installed")
        elif chrony_installed and not chrony_status["active"]:
            issues.append("chrony is installed but not running")
        elif chrony_installed and not chrony_status["enabled"]:
            issues.append("chrony is installed but not enabled")
        elif chrony_installed and not chrony_config["has_valid_config"]:
            issues.append("chrony is installed but has no valid server configuration")
        elif timesyncd_installed and not timesyncd_status["active"]:
            issues.append("systemd-timesyncd is installed but not running")
        elif timesyncd_installed and not timesyncd_status["enabled"]:
            issues.append("systemd-timesyncd is installed but not enabled")
        elif timesyncd_installed and not timesyncd_config["has_valid_config"]:
            issues.append("systemd-timesyncd is installed but has no valid NTP configuration")
        else:
            issues.append("No time synchronization service is properly configured")

        install_chrony_cmd = self._platform_remediation_command(
            "install_packages",
            "sudo dnf install chrony",
            packages="chrony",
        )
        enable_chronyd_cmd = self._platform_remediation_command(
            "enable_service",
            "sudo systemctl enable chronyd",
            service="chronyd",
        )
        start_chronyd_cmd = self._platform_remediation_command(
            "start_service",
            "sudo systemctl start chronyd",
            service="chronyd",
        )
        install_timesyncd_cmd = self._platform_remediation_command(
            "install_packages",
            "sudo dnf install systemd-timesyncd",
            packages="systemd-timesyncd",
        )
        enable_timesyncd_cmd = self._platform_remediation_command(
            "enable_service",
            "sudo systemctl enable systemd-timesyncd",
            service="systemd-timesyncd",
        )
        start_timesyncd_cmd = self._platform_remediation_command(
            "start_service",
            "sudo systemctl start systemd-timesyncd",
            service="systemd-timesyncd",
        )

        # Build remediation
        remediation_parts = [
            "Install and configure a time synchronization service:",
            "",
            "Option 1 - Install chrony (recommended for servers):",
            f"   {install_chrony_cmd}",
            f"   {enable_chronyd_cmd}",
            f"   {start_chronyd_cmd}",
            "   # Edit /etc/chrony.conf to configure NTP servers",
            "",
            "Option 2 - Install systemd-timesyncd (lightweight):",
            f"   {install_timesyncd_cmd}",
            f"   {enable_timesyncd_cmd}",
            f"   {start_timesyncd_cmd}",
            "   # Edit /etc/systemd/timesyncd.conf to configure NTP servers",
            "",
            "Verify configuration:",
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
