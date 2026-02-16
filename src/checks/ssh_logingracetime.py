"""
CIS Audit Check: SSH LoginGraceTime (5.1.17)

Ensures LoginGraceTime is set to 1 minute (60 seconds) or less
to limit the time for successful authentication.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHLoginGraceTimeCheck(BaseCheck):
    """Check SSH LoginGraceTime configuration."""

    id = "ssh_logingracetime"
    name = "SSH LoginGraceTime"
    description = (
        "Verifies that LoginGraceTime is set to 1 minute (60 seconds) "
        "or less to limit the time allowed for successful authentication"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    # CIS recommends LoginGraceTime <= 60 seconds (1 minute)
    MAX_SECONDS = 60

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for LoginGraceTime setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "logingracetime": None,
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

                        match = re.match(r"^LoginGraceTime\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1)
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["logingracetime"] = value
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

                                match = re.match(r"^LoginGraceTime\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1)
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["logingracetime"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _parse_time_value(self, value: str) -> int | None:
        """Parse a time value with optional suffix.

        Args:
            value: Time value string (e.g., "60", "1m", "2h")

        Returns:
            Time in seconds, or None if invalid
        """
        value = value.strip().lower()

        # Handle numeric values (assumed to be seconds)
        if value.isdigit():
            return int(value)

        # Handle suffixed values
        if value.endswith("s"):
            try:
                return int(value[:-1])
            except ValueError:
                return None
        elif value.endswith("m"):
            try:
                return int(value[:-1]) * 60
            except ValueError:
                return None
        elif value.endswith("h"):
            try:
                return int(value[:-1]) * 3600
            except ValueError:
                return None
        elif value.endswith("d"):
            try:
                return int(value[:-1]) * 86400
            except ValueError:
                return None

        # Try to parse as plain number
        try:
            return int(value)
        except ValueError:
            return None

    def run(self) -> CheckResult:
        """Execute the SSH LoginGraceTime check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default LoginGraceTime is 120 seconds (2 minutes)
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "LoginGraceTime not explicitly set. Default is 120 seconds (2 minutes), "
                    f"which exceeds the recommended maximum of {self.MAX_SECONDS} seconds (1 minute)."
                ),
                remediation=(
                    "Edit /etc/ssh/sshd_config and set:\n"
                    f"LoginGraceTime {self.MAX_SECONDS}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "This limits the time allowed for successful authentication, "
                    "reducing the window for brute force attacks."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["logingracetime"] is None:
            # Not explicitly set - default is 120 seconds
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "LoginGraceTime directive not found. Default is 120 seconds (2 minutes), "
                    f"which exceeds the recommended maximum of {self.MAX_SECONDS} seconds (1 minute)."
                ),
                remediation=(
                    "Edit /etc/ssh/sshd_config and set:\n"
                    f"LoginGraceTime {self.MAX_SECONDS}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "This limits the time allowed for successful authentication, "
                    "reducing the window for brute force attacks."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Parse the time value
        seconds = self._parse_time_value(config["logingracetime"])

        if seconds is None:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"LoginGraceTime has invalid value: '{config['logingracetime']}'",
                remediation=(
                    f"Check {config['config_file']} and set a valid time value:\n"
                    f"LoginGraceTime {self.MAX_SECONDS}\n\n"
                    "Valid formats: 60 (seconds), 60s, 1m, 1h"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if seconds <= self.MAX_SECONDS:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"LoginGraceTime is set to {config['logingracetime']} "
                    f"({seconds} seconds ≤ {self.MAX_SECONDS} seconds) - secure configuration"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Value exceeds maximum
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"LoginGraceTime is set to {config['logingracetime']} "
                f"({seconds} seconds exceeds recommended maximum of {self.MAX_SECONDS} seconds)"
            ),
            remediation=(
                f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                f"LoginGraceTime {self.MAX_SECONDS}\n\n"
                "Then reload SSH:\n"
                "systemctl reload sshd\n\n"
                "This limits the time allowed for successful authentication, "
                "reducing the window for brute force attacks."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
