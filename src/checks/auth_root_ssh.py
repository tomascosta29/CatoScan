"""
CIS Audit Check: Root SSH Login Restriction

Checks if SSH root login is properly restricted to prevent
direct root access via SSH.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class RootSSHCheck(BaseCheck):
    """Check for SSH root login configuration."""

    id = "auth_root_ssh"
    name = "Root SSH Login Restriction"
    description = (
        "Verifies that root login via SSH is disabled or restricted "
        "to prevent direct root access"
    )
    severity = Severity.HIGH
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    # Secure values for PermitRootLogin
    SECURE_VALUES = {"no", "prohibit-password", "without-password"}
    INSECURE_VALUES = {"yes"}

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for PermitRootLogin setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "permit_root_login": None,
            "config_file": None,
            "config_line": None,
            "files_read": [],
            "all_settings": [],
        }

        # Read main config file first
        if os.path.exists(self.SSHD_CONFIG):
            config["files_read"].append(self.SSHD_CONFIG)
            try:
                with open(self.SSHD_CONFIG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        match = re.match(r"^PermitRootLogin\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["permit_root_login"] = value
                            config["config_file"] = self.SSHD_CONFIG
                            config["config_line"] = line

            except (IOError, OSError):
                pass

        # Read config snippets from sshd_config.d (these override main config)
        if os.path.isdir(self.SSHD_CONFIG_D):
            try:
                # Sort to ensure consistent order
                for conf_file in sorted(Path(self.SSHD_CONFIG_D).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                match = re.match(r"^PermitRootLogin\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins (config.d files override main config)
                                    config["permit_root_login"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_sshd_service(self) -> dict:
        """Check if sshd service is installed and running.

        Returns:
            Dictionary with service status
        """
        status = {
            "installed": False,
            "running": False,
            "enabled": False,
        }

        # Check if sshd binary exists
        sshd_paths = ["/usr/sbin/sshd", "/sbin/sshd"]
        for path in sshd_paths:
            if os.path.exists(path):
                status["installed"] = True
                break

        # Check if service is running (simple check for listening on port 22)
        try:
            # Check for listening sshd process
            with open("/proc/net/tcp", "r") as f:
                content = f.read()
                # Port 22 in hex is 0016
                if "0016" in content:
                    status["running"] = True
        except (IOError, OSError):
            pass

        return status

    def run(self) -> CheckResult:
        """Execute the root SSH login check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if SSH is installed
        service_status = self._check_sshd_service()

        if not service_status["installed"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH daemon is not installed - root SSH login restriction not applicable",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"service_status": service_status},
            )

        # Parse SSH configuration
        config = self._parse_sshd_config()

        if not config["files_read"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Cannot read SSH configuration files",
                remediation=(
                    "Ensure /etc/ssh/sshd_config exists and is readable.\n"
                    "If SSH is installed, check file permissions."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Check PermitRootLogin setting
        if config["permit_root_login"] is None:
            # Not explicitly set - check default behavior
            # Modern OpenSSH defaults to 'prohibit-password' which is secure
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "PermitRootLogin is not explicitly set. "
                    "Modern OpenSSH defaults to 'prohibit-password' which is secure. "
                    "Consider explicitly setting it for clarity."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        value = config["permit_root_login"]

        if value in self.INSECURE_VALUES:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"CRITICAL: PermitRootLogin is set to '{value}' - root can login with password via SSH",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    "PermitRootLogin no\n\n"
                    "Or, if you need key-based root login:\n"
                    "PermitRootLogin prohibit-password\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "Note: Ensure you have alternative sudo access before disabling root login!"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if value in self.SECURE_VALUES:
            if value == "no":
                message = "PermitRootLogin is set to 'no' - root login via SSH is completely disabled"
            else:
                message = f"PermitRootLogin is set to '{value}' - root can only login with key authentication"

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=message,
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"PermitRootLogin has unrecognized value: '{value}'",
            remediation=(
                f"Check {config['config_file']} and set a valid PermitRootLogin value:\n"
                "- 'no' - completely disable root login\n"
                "- 'prohibit-password' or 'without-password' - key auth only\n"
                "- 'forced-commands-only' - only for forced commands (rare)"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
