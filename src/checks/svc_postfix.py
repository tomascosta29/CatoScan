"""
CIS Audit Check: Postfix Local-Only Mode

Checks if Postfix is configured for local-only mode (CIS 2.2.15).
"""

import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class PostfixLocalOnlyCheck(BaseCheck):
    """Check if Postfix is configured for local-only mode."""

    id = "svc_postfix"
    name = "Postfix Local-Only Mode"
    description = (
        "Verifies that Postfix is configured for local-only mode "
        "to prevent unauthorized mail relay"
    )
    severity = Severity.MEDIUM
    requires_root = True

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

    def _get_postfix_config(self) -> dict[str, str]:
        """Get Postfix configuration.

        Returns:
            Dictionary with Postfix configuration
        """
        config: dict[str, str] = {
            "inet_interfaces": "",
            "inet_protocols": "",
        }

        try:
            result = subprocess.run(
                ["postconf", "inet_interfaces", "inet_protocols"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip("'")
                        if key in config:
                            config[key] = value
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return config

    def run(self) -> CheckResult:
        """Execute the Postfix local-only mode check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if postfix package is installed
        postfix_installed = self._check_package_installed("postfix")

        # Check postfix service status
        service_status = self._check_service_status("postfix")

        # If postfix is not installed, check passes
        if not postfix_installed and not service_status["installed"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Postfix is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "postfix_installed": False,
                    "service_status": service_status,
                },
            )

        # Get Postfix configuration
        config = self._get_postfix_config()

        details = {
            "postfix_installed": postfix_installed,
            "service_status": service_status,
            "config": config,
        }

        # Check if configured for local-only mode
        inet_interfaces = config.get("inet_interfaces", "")
        is_local_only = (
            inet_interfaces == "loopback-only" or
            inet_interfaces == "localhost" or
            inet_interfaces == "127.0.0.1" or
            "loopback" in inet_interfaces.lower()
        )

        if is_local_only:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Postfix is configured for local-only mode",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        reload_cmd = self._platform_reload_service_command("postfix")
        remove_cmd = self._platform_remove_packages_command("postfix")

        remediation = (
            "Configure Postfix for local-only mode:\n\n"
            "1. Edit Postfix configuration:\n"
            "   sudo postconf -e 'inet_interfaces = loopback-only'\n\n"
            "2. Reload Postfix:\n"
            f"   {reload_cmd}\n\n"
            "3. Verify configuration:\n"
            "   postconf inet_interfaces\n\n"
            "Note: If Postfix is not needed, consider removing it:\n"
            f"   {remove_cmd}"
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Postfix is not configured for local-only mode (inet_interfaces = {inet_interfaces})",
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
