"""
CIS Audit Check: SSH Client StrictHostKeyChecking (5.2.x)

Ensures SSH client StrictHostKeyChecking is enabled to prevent
man-in-the-middle attacks by verifying host keys.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientStrictHostCheck(BaseCheck):
    """Check SSH client StrictHostKeyChecking configuration."""

    id = "ssh_client_strict_host"
    name = "SSH Client StrictHostKeyChecking"
    description = (
        "Verifies that SSH client StrictHostKeyChecking is enabled "
        "to prevent man-in-the-middle attacks by verifying host keys"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for StrictHostKeyChecking setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "strict_host_checking": None,
            "config_file": None,
            "config_line": None,
            "files_read": [],
            "all_settings": [],
        }

        # Read main config file first
        if os.path.exists(self.SSH_CONFIG):
            config["files_read"].append(self.SSH_CONFIG)
            try:
                with open(self.SSH_CONFIG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        match = re.match(r"^StrictHostKeyChecking\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["strict_host_checking"] = value
                            config["config_file"] = self.SSH_CONFIG
                            config["config_line"] = line

            except (IOError, OSError):
                pass

        # Read config snippets from ssh_config.d (these override main config)
        if os.path.isdir(self.SSH_CONFIG_D):
            try:
                for conf_file in sorted(Path(self.SSH_CONFIG_D).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                match = re.match(r"^StrictHostKeyChecking\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["strict_host_checking"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH client StrictHostKeyChecking check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if config["strict_host_checking"] is None:
            # Not explicitly set - default is ask (not as secure as yes)
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "StrictHostKeyChecking not explicitly set. Default is 'ask', "
                    "which allows connections to unknown hosts."
                ),
                remediation=(
                    f"Edit {self.SSH_CONFIG} and set:\n"
                    "StrictHostKeyChecking yes\n\n"
                    "This ensures SSH will refuse to connect to hosts with unknown "
                    "or changed host keys, preventing man-in-the-middle attacks."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        strict_host = config["strict_host_checking"]

        if strict_host == "yes":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH client StrictHostKeyChecking is enabled - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if strict_host in ("no", "ask", "off"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"SSH client StrictHostKeyChecking is set to '{strict_host}' - security risk",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    "StrictHostKeyChecking yes\n\n"
                    "When set to 'yes', SSH will refuse to connect to hosts with unknown "
                    "or changed host keys, preventing man-in-the-middle attacks."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"StrictHostKeyChecking has unrecognized value: '{strict_host}'",
            remediation=(
                f"Check {config['config_file']} and set:\n"
                "StrictHostKeyChecking yes"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
