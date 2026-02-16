"""
CIS Audit Check: SSH MaxSessions (5.1.22)

Ensures MaxSessions is set to 10 or less to limit concurrent connections.
This prevents resource exhaustion and limits attack surface.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHMaxSessionsCheck(BaseCheck):
    """Check SSH MaxSessions configuration."""

    id = "ssh_maxsessions"
    name = "SSH MaxSessions"
    description = (
        "Verifies that MaxSessions is set to 10 or less "
        "to limit concurrent connections and prevent resource exhaustion"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"
    MAX_ALLOWED = 10

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for MaxSessions setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "maxsessions": None,
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

                        match = re.match(r"^MaxSessions\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1)
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["maxsessions"] = value
                            config["config_file"] = self.SSHD_CONFIG
                            config["config_line"] = line

            except (IOError, OSError):
                pass

        # Read config snippets from sshd_config.d (these override main config)
        if os.path.isdir(self.SSHD_CONFIG_D):
            try:
                for conf_file in sorted(Path(self.SSHD_CONFIG_D).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                match = re.match(r"^MaxSessions\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1)
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["maxsessions"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH MaxSessions check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default MaxSessions is 10, which meets CIS recommendation
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"MaxSessions not explicitly set. Default is 10, "
                    f"which meets the recommended maximum of {self.MAX_ALLOWED}."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["maxsessions"] is None:
            # Not explicitly set - default is 10
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"MaxSessions directive not found. Default is 10, "
                    f"which meets the recommended maximum of {self.MAX_ALLOWED}."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        try:
            maxsessions = int(config["maxsessions"])
        except ValueError:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"MaxSessions has invalid value: '{config['maxsessions']}'",
                remediation=(
                    f"Check {config['config_file']} and set a valid integer:\n"
                    f"MaxSessions {self.MAX_ALLOWED}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if maxsessions <= self.MAX_ALLOWED:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"MaxSessions is set to {maxsessions} (≤ {self.MAX_ALLOWED}) - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Value exceeds maximum
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"MaxSessions is set to {maxsessions} (exceeds recommended maximum of {self.MAX_ALLOWED})",
            remediation=(
                f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                f"MaxSessions {self.MAX_ALLOWED}\n\n"
                "Then reload SSH:\n"
                "systemctl reload sshd\n\n"
                "Lower values limit the number of concurrent sessions per connection, "
                "helping prevent resource exhaustion and limiting attack surface."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
