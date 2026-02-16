"""
CIS Audit Check: AIDE Installed

Checks if AIDE (Advanced Intrusion Detection Environment) is installed (CIS 1.2.1).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AIDEInstalledCheck(BaseCheck):
    """Check if AIDE is installed."""

    id = "fs_aide"
    name = "AIDE Installed"
    description = (
        "Verifies that AIDE (Advanced Intrusion Detection Environment) "
        "is installed for file integrity monitoring"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # AIDE package and binary names
    AIDE_PACKAGES = ["aide"]
    AIDE_BINARIES = ["/usr/sbin/aide", "/usr/bin/aide", "/sbin/aide", "/bin/aide"]

    # AIDE configuration files
    AIDE_CONFIGS = [
        "/etc/aide.conf",
        "/etc/aide/aide.conf",
    ]

    def _check_package_installed(self) -> dict:
        """Check if AIDE package is installed.

        Returns:
            Dictionary with package check results
        """
        result = {
            "installed": False,
            "package": None,
            "version": None,
        }

        for package in self.AIDE_PACKAGES:
            try:
                rpm_result = subprocess.run(
                    ["rpm", "-q", package],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if rpm_result.returncode == 0:
                    result["installed"] = True
                    result["package"] = package
                    result["version"] = rpm_result.stdout.strip()
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return result

    def _check_binary_exists(self) -> dict:
        """Check if AIDE binary exists.

        Returns:
            Dictionary with binary check results
        """
        result = {
            "exists": False,
            "path": None,
            "version": None,
        }

        for binary_path in self.AIDE_BINARIES:
            binary = Path(binary_path)
            if binary.exists():
                result["exists"] = True
                result["path"] = binary_path

                # Try to get version
                try:
                    version_result = subprocess.run(
                        [binary_path, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if version_result.returncode == 0:
                        result["version"] = version_result.stdout.strip().split("\n")[0]
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

                break

        return result

    def _check_config_exists(self) -> dict:
        """Check if AIDE configuration file exists.

        Returns:
            Dictionary with config check results
        """
        result = {
            "exists": False,
            "path": None,
        }

        for config_path in self.AIDE_CONFIGS:
            config = Path(config_path)
            if config.exists():
                result["exists"] = True
                result["path"] = config_path
                break

        return result

    def _check_database_exists(self) -> dict:
        """Check if AIDE database exists.

        Returns:
            Dictionary with database check results
        """
        result = {
            "exists": False,
            "path": None,
        }

        # Common AIDE database locations
        database_paths = [
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide/aide.db.new.gz",
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.new",
            "/etc/aide/aide.db.gz",
            "/etc/aide/aide.db.new.gz",
        ]

        for db_path in database_paths:
            db = Path(db_path)
            if db.exists():
                result["exists"] = True
                result["path"] = db_path
                break

        return result

    def run(self) -> CheckResult:
        """Execute the AIDE installed check.

        Returns:
            CheckResult with the outcome of the check
        """
        package_info = self._check_package_installed()
        binary_info = self._check_binary_exists()
        config_info = self._check_config_exists()
        database_info = self._check_database_exists()

        details = {
            "package": package_info,
            "binary": binary_info,
            "config": config_info,
            "database": database_info,
        }

        # Determine result
        if package_info["installed"] and binary_info["exists"]:
            message = "AIDE is installed"
            if package_info["version"]:
                message += f" ({package_info['version']})"

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=message,
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not package_info["installed"]:
            issues.append("AIDE package is not installed")
        if not binary_info["exists"]:
            issues.append("AIDE binary not found")

        # Build remediation
        remediation_parts = [
            "Install AIDE for file integrity monitoring:",
            "",
            "1. Install AIDE package:",
            "   sudo dnf install aide",
            "",
            "2. Initialize AIDE database (this may take a while):",
            "   sudo aide --init",
            "",
            "3. Move the new database to the active location:",
            "   sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
            "",
            "4. Verify AIDE is working:",
            "   sudo aide --check",
            "",
            "5. Configure AIDE to run regularly via cron (see fs_aide_cron check)",
            "",
            "Note: Initial database creation can take significant time and resources.",
            "      Consider running during off-peak hours.",
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
