"""
CIS Audit Check: SSH LogLevel (5.1.5)

Ensures SSH is configured with an appropriate LogLevel.
Recommended: INFO or VERBOSE (DEBUG levels may expose sensitive data).
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHLogLevelCheck(BaseCheck):
    """Check SSH LogLevel configuration."""

    id = "ssh_loglevel"
    name = "SSH LogLevel"
    description = (
        "Verifies that SSH is configured with an appropriate LogLevel "
        "(INFO or VERBOSE recommended; DEBUG levels may expose sensitive data)"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    # Acceptable log levels (in order of verbosity)
    ACCEPTABLE_LEVELS = {"QUIET", "FATAL", "ERROR", "INFO", "VERBOSE"}
    # Insecure log levels (may expose sensitive data)
    INSECURE_LEVELS = {"DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"}

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for LogLevel setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "loglevel": None,
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

                        match = re.match(r"^LogLevel\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).upper()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["loglevel"] = value
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

                                match = re.match(r"^LogLevel\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).upper()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["loglevel"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH LogLevel check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default LogLevel is INFO which is acceptable
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "LogLevel not explicitly set. Default is INFO, "
                    "which is acceptable."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["loglevel"] is None:
            # Not explicitly set - default is INFO
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "LogLevel directive not found. Default is INFO, "
                    "which is acceptable."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        loglevel = config["loglevel"]

        # Check if it's an acceptable level
        if loglevel in self.ACCEPTABLE_LEVELS:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"LogLevel is set to '{loglevel}' - acceptable configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Check for insecure debug levels
        if loglevel in self.INSECURE_LEVELS:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"LogLevel is set to '{loglevel}' - may expose sensitive data",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    "LogLevel INFO\n\n"
                    "Or for more detailed logging:\n"
                    "LogLevel VERBOSE\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "DEBUG levels may log sensitive information including passwords."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"LogLevel has unrecognized value: '{loglevel}'",
            remediation=(
                f"Check {config['config_file']} and set a valid LogLevel:\n"
                "LogLevel INFO\n\n"
                "Valid levels: QUIET, FATAL, ERROR, INFO, VERBOSE"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
