"""
CIS Audit Check: SSH PermitEmptyPasswords (5.1.11)

Ensures empty passwords are not permitted for SSH authentication.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHPermitEmptyPasswordsCheck(BaseCheck):
    """Check SSH PermitEmptyPasswords configuration."""

    id = "ssh_permitemptypasswords"
    name = "SSH PermitEmptyPasswords"
    description = (
        "Verifies that empty passwords are not permitted "
        "for SSH authentication"
    )
    severity = Severity.HIGH
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for PermitEmptyPasswords setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "permitemptypasswords": None,
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

                        match = re.match(r"^PermitEmptyPasswords\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["permitemptypasswords"] = value
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

                                match = re.match(r"^PermitEmptyPasswords\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["permitemptypasswords"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH PermitEmptyPasswords check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default PermitEmptyPasswords is no
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "PermitEmptyPasswords not explicitly set. Default is 'no', "
                    "which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["permitemptypasswords"] is None:
            # Not explicitly set - default is no
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "PermitEmptyPasswords directive not found. Default is 'no', "
                    "which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        permitemptypasswords = config["permitemptypasswords"]

        if permitemptypasswords == "no":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="PermitEmptyPasswords is disabled - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if permitemptypasswords == "yes":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="CRITICAL: PermitEmptyPasswords is enabled - accounts with empty passwords can login via SSH",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    "PermitEmptyPasswords no\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "Allowing empty passwords is a critical security risk "
                    "as it allows anyone to access accounts without authentication."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"PermitEmptyPasswords has unrecognized value: '{permitemptypasswords}'",
            remediation=(
                f"Check {config['config_file']} and set:\n"
                "PermitEmptyPasswords no"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
