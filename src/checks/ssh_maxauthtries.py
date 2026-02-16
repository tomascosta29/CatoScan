"""
CIS Audit Check: SSH MaxAuthTries (5.1.7)

Ensures MaxAuthTries is set to 4 or less to limit brute force attempts.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHMaxAuthTriesCheck(BaseCheck):
    """Check SSH MaxAuthTries configuration."""

    id = "ssh_maxauthtries"
    name = "SSH MaxAuthTries"
    description = (
        "Verifies that MaxAuthTries is set to 4 or less "
        "to limit brute force authentication attempts"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"
    MAX_ALLOWED = 4

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for MaxAuthTries setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "maxauthtries": None,
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

                        match = re.match(r"^MaxAuthTries\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1)
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["maxauthtries"] = value
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

                                match = re.match(r"^MaxAuthTries\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1)
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["maxauthtries"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH MaxAuthTries check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default MaxAuthTries is 6, which is higher than CIS recommendation
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "MaxAuthTries not explicitly set. Default is 6, "
                    f"which exceeds the recommended maximum of {self.MAX_ALLOWED}."
                ),
                remediation=(
                    "Edit /etc/ssh/sshd_config and set:\n"
                    f"MaxAuthTries {self.MAX_ALLOWED}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["maxauthtries"] is None:
            # Not explicitly set - default is 6
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "MaxAuthTries directive not found. Default is 6, "
                    f"which exceeds the recommended maximum of {self.MAX_ALLOWED}."
                ),
                remediation=(
                    "Edit /etc/ssh/sshd_config and set:\n"
                    f"MaxAuthTries {self.MAX_ALLOWED}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        try:
            maxauthtries = int(config["maxauthtries"])
        except ValueError:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"MaxAuthTries has invalid value: '{config['maxauthtries']}'",
                remediation=(
                    f"Check {config['config_file']} and set a valid integer:\n"
                    f"MaxAuthTries {self.MAX_ALLOWED}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if maxauthtries <= self.MAX_ALLOWED:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"MaxAuthTries is set to {maxauthtries} (≤ {self.MAX_ALLOWED}) - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Value exceeds maximum
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"MaxAuthTries is set to {maxauthtries} (exceeds recommended maximum of {self.MAX_ALLOWED})",
            remediation=(
                f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                f"MaxAuthTries {self.MAX_ALLOWED}\n\n"
                "Then reload SSH:\n"
                "systemctl reload sshd\n\n"
                "Lower values limit brute force authentication attempts."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
