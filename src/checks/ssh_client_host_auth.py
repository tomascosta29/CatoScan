"""
CIS Audit Check: SSH Client HostbasedAuthentication (5.2.x)

Ensures SSH client host-based authentication is disabled to prevent
authentication based on host trust relationships.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientHostAuthCheck(BaseCheck):
    """Check SSH client HostbasedAuthentication configuration."""

    id = "ssh_client_host_auth"
    name = "SSH Client HostbasedAuthentication"
    description = (
        "Verifies that SSH client host-based authentication is disabled "
        "to prevent authentication based on host trust relationships"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for HostbasedAuthentication setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "hostbasedauth": None,
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

                        match = re.match(r"^HostbasedAuthentication\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["hostbasedauth"] = value
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

                                match = re.match(r"^HostbasedAuthentication\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["hostbasedauth"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH client HostbasedAuthentication check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if config["hostbasedauth"] is None:
            # Not explicitly set - default is no
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "HostbasedAuthentication directive not found in SSH client config. "
                    "Default is 'no', which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        hostbasedauth = config["hostbasedauth"]

        if hostbasedauth == "no":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH client HostbasedAuthentication is disabled - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if hostbasedauth == "yes":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH client HostbasedAuthentication is enabled - security risk",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    "HostbasedAuthentication no\n\n"
                    "Host-based authentication allows authentication based on "
                    "host trust relationships, which can be spoofed."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"HostbasedAuthentication has unrecognized value: '{hostbasedauth}'",
            remediation=(
                f"Check {config['config_file']} and set:\n"
                "HostbasedAuthentication no"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
