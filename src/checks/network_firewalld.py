"""
CIS Audit Check: FirewallD Service

Checks if firewalld is installed, running, and enabled.
"""

import os

from src.core.check import BaseCheck, CheckResult, Severity


class FirewalldCheck(BaseCheck):
    """Check for firewalld installation and service status."""

    id = "network_firewalld"
    name = "FirewallD Service Status"
    description = (
        "Verifies that firewalld is installed, running, "
        "and enabled to start on boot"
    )
    severity = Severity.HIGH
    requires_root = True

    def _is_firewalld_installed(self) -> tuple[bool, str]:
        """Check if firewalld package is installed.

        Returns:
            Tuple of (installed, method_used)
        """
        installed, method = self.platform_context.check_package_installed("firewalld")
        if installed:
            return True, method

        # Check for firewalld binary
        if os.path.exists("/usr/sbin/firewalld") or os.path.exists("/usr/bin/firewalld"):
            return True, "binary"

        return False, "none"

    def _is_service_running(self) -> tuple[bool, str]:
        """Check if firewalld service is running.

        Returns:
            Tuple of (running, status_output)
        """
        return self.platform_context.check_service_active("firewalld")

    def _is_service_enabled(self) -> tuple[bool, str]:
        """Check if firewalld service is enabled to start on boot.

        Returns:
            Tuple of (enabled, status_output)
        """
        enabled, status = self.platform_context.check_service_enabled("firewalld")
        return enabled, status

    def _cmd_or_default(self, template_key: str, default: str, **kwargs: str) -> str:
        """Render command from platform profile with fallback."""
        rendered = self.platform_context.render_remediation(template_key, **kwargs)
        return rendered if rendered else default

    def run(self) -> CheckResult:
        """Execute the firewalld check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "installed": False,
            "installation_method": None,
            "running": False,
            "running_status": None,
            "enabled": False,
            "enabled_status": None,
        }

        # Check if firewalld is installed
        installed, method = self._is_firewalld_installed()
        details["installed"] = installed
        details["installation_method"] = method

        if not installed:
            install_cmd = self._cmd_or_default(
                "install_packages",
                "sudo dnf install firewalld",
                packages="firewalld",
            )
            enable_cmd = self._cmd_or_default(
                "enable_service",
                "sudo systemctl enable firewalld",
                service="firewalld",
            )
            start_cmd = self._cmd_or_default(
                "start_service",
                "sudo systemctl start firewalld",
                service="firewalld",
            )
            status_cmd = self._cmd_or_default(
                "status_service",
                "sudo systemctl status firewalld",
                service="firewalld",
            )

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="firewalld is not installed on this system",
                remediation=(
                    "Install and enable firewalld:\n"
                    f"1. Install: {install_cmd}\n"
                    f"2. Enable service: {enable_cmd}\n"
                    f"3. Start service: {start_cmd}\n"
                    f"4. Verify status: {status_cmd}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if service is running
        running, running_status = self._is_service_running()
        details["running"] = running
        details["running_status"] = running_status

        # Check if service is enabled
        enabled, enabled_status = self._is_service_enabled()
        details["enabled"] = enabled
        details["enabled_status"] = enabled_status

        # Determine overall result
        if running and enabled:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="firewalld is installed, running, and enabled on boot",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not running and not enabled:
            enable_cmd = self._cmd_or_default(
                "enable_service",
                "sudo systemctl enable firewalld",
                service="firewalld",
            )
            start_cmd = self._cmd_or_default(
                "start_service",
                "sudo systemctl start firewalld",
                service="firewalld",
            )
            status_cmd = self._cmd_or_default(
                "status_service",
                "sudo systemctl status firewalld",
                service="firewalld",
            )

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="firewalld is installed but not running and not enabled",
                remediation=(
                    "Enable and start firewalld:\n"
                    f"1. Enable on boot: {enable_cmd}\n"
                    f"2. Start now: {start_cmd}\n"
                    f"3. Verify status: {status_cmd}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not running:
            start_cmd = self._cmd_or_default(
                "start_service",
                "sudo systemctl start firewalld",
                service="firewalld",
            )
            status_cmd = self._cmd_or_default(
                "status_service",
                "sudo systemctl status firewalld",
                service="firewalld",
            )

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="firewalld is installed and enabled but not currently running",
                remediation=(
                    "Start firewalld:\n"
                    f"1. Start service: {start_cmd}\n"
                    "2. Check for errors: sudo journalctl -u firewalld -n 50\n"
                    f"3. Verify status: {status_cmd}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Running but not enabled
        enable_cmd = self._cmd_or_default(
            "enable_service",
            "sudo systemctl enable firewalld",
            service="firewalld",
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="firewalld is installed and running but not enabled on boot",
            remediation=(
                "Enable firewalld to start on boot:\n"
                f"1. Enable service: {enable_cmd}\n"
                "2. Verify: sudo systemctl is-enabled firewalld"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
