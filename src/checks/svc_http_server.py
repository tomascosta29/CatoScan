"""
CIS Audit Check: HTTP Server Not Installed

Checks if HTTP server is not installed (CIS 2.2.10).
"""

from src.core.check import BaseCheck, CheckResult, Severity


class HTTPServerNotInstalledCheck(BaseCheck):
    """Check if HTTP server is not installed."""

    id = "svc_http_server"
    name = "HTTP Server Not Installed"
    description = (
        "Verifies that HTTP server is not installed to prevent "
        "unnecessary web services"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Common HTTP server packages
    HTTP_PACKAGES = ["httpd", "nginx", "lighttpd"]
    HTTP_SERVICES = ["httpd", "nginx", "lighttpd"]

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
        """Execute the HTTP server not installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if any HTTP packages are installed
        installed_packages = []
        for package in self.HTTP_PACKAGES:
            if self._check_package_installed(package):
                installed_packages.append(package)

        # Check HTTP service status
        service_statuses = []
        active_services = []
        for service in self.HTTP_SERVICES:
            status = self._check_service_status(service)
            service_statuses.append(status)
            if status["installed"]:
                active_services.append(service)

        details = {
            "installed_packages": installed_packages,
            "service_statuses": service_statuses,
        }

        # Determine result
        if not installed_packages and not active_services:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="HTTP server is not installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build remediation
        remove_cmd = self._platform_remove_packages_command("httpd nginx lighttpd")
        status_cmd = self._platform_status_service_command("httpd")

        remediation = (
            "Remove server packages:\n\n"
            "1. Remove packages:\n"
            f"   {remove_cmd}\n\n"
            "2. Verify packages and services are removed:\n"
            "   rpm -q httpd\n"
            f"   {status_cmd}"
        )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
