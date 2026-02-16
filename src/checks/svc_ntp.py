"""
CIS Audit Check: NTP Server Not Installed

Ensures that NTP server is not installed on the system.
Time synchronization should be handled by chrony or systemd-timesyncd
as a client only, not as an NTP server.
"""

from src.core.check import BaseCheck, CheckResult, Severity


class NTPServerNotInstalledCheck(BaseCheck):
    """Check if NTP server is not installed."""

    id = "svc_ntp"
    name = "NTP Server Not Installed"
    description = (
        "Verifies that NTP server is not installed. "
        "Time synchronization should be handled by chrony or systemd-timesyncd "
        "as a client only"
    )
    severity = Severity.MEDIUM
    requires_root = True

    NTP_PACKAGES = [
        "ntp",
        "ntp-server",
        "openntpd",
    ]

    NTP_SERVICES = [
        "ntpd",
        "ntp",
        "openntpd",
    ]

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

    def run(self) -> CheckResult:
        """Execute the NTP server not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        installed_packages = []
        running_services = []

        # Check for NTP packages
        for package in self.NTP_PACKAGES:
            if self._check_package_installed(package):
                installed_packages.append(package)

        # Check for NTP services
        for service in self.NTP_SERVICES:
            service_status = self._check_service_status(service)
            if service_status["installed"] or service_status["active"] or service_status["enabled"]:
                running_services.append(service_status)

        details = {
            "installed_packages": installed_packages,
            "service_status": running_services,
        }

        # Check if any NTP server is installed or running
        if installed_packages or running_services:
            issues = []
            if installed_packages:
                issues.append(f"NTP packages installed: {', '.join(installed_packages)}")
            if running_services:
                active_services = [s["service"] for s in running_services if s["active"]]
                if active_services:
                    issues.append(f"NTP services active: {', '.join(active_services)}")

            remove_ntp_cmd = self._platform_remove_packages_command("ntp")
            install_chrony_cmd = self._platform_install_packages_command("chrony")
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

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"NTP server is installed or running: {'; '.join(issues)}",
                remediation=(
                    "Remove NTP server and use chrony or systemd-timesyncd instead:\n\n"
                    "1. Stop and disable NTP service:\n"
                    "   sudo systemctl stop ntpd\n"
                    "   sudo systemctl disable ntpd\n\n"
                    "2. Remove NTP package:\n"
                    f"   {remove_ntp_cmd}\n\n"
                    "3. Install and configure chrony (recommended):\n"
                    f"   {install_chrony_cmd}\n"
                    f"   {enable_chronyd_cmd}\n"
                    f"   {start_chronyd_cmd}\n\n"
                    "4. Verify time synchronization:\n"
                    "   timedatectl status\n\n"
                    "Note: Time synchronization clients (chrony, systemd-timesyncd) "
                    "are preferred over NTP server for most systems."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="NTP server is not installed",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
