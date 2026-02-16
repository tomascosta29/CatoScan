"""
CIS Audit Check: SSH Client Protocol Version (5.2.x)

Ensures SSH client is configured to use Protocol 2 only.
Protocol 1 has known security vulnerabilities and should not be used.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientProtocolCheck(BaseCheck):
    """Check SSH client protocol version configuration."""

    id = "ssh_client_protocol"
    name = "SSH Client Protocol Version 2"
    description = (
        "Verifies that SSH client is configured to use Protocol 2 only, "
        "as Protocol 1 has known security vulnerabilities"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for Protocol setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "protocol": None,
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

                        match = re.match(r"^Protocol\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1)
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["protocol"] = value
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

                                match = re.match(r"^Protocol\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1)
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["protocol"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH client protocol check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if config["protocol"] is None:
            # Not explicitly set - modern default is Protocol 2
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "Protocol directive not found in SSH client config. "
                    "Modern OpenSSH defaults to Protocol 2 only."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        protocol_value = config["protocol"]

        # Check if only Protocol 2 is specified
        if protocol_value == "2":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH client Protocol is set to 2 only - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Check for insecure configurations
        if protocol_value == "1":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="CRITICAL: SSH client Protocol is set to 1 - vulnerable to attacks",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    "Protocol 2\n\n"
                    "Protocol 1 has known security vulnerabilities and should never be used."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if protocol_value in ("1,2", "2,1"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH client Protocol allows both 1 and 2 - vulnerable to downgrade attacks",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    "Protocol 2\n\n"
                    "Allowing Protocol 1 exposes the system to known vulnerabilities."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Protocol has unrecognized value: '{protocol_value}'",
            remediation=(
                f"Check {config['config_file']} and set Protocol to '2' only:\n"
                "Protocol 2"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
