"""
CIS Audit Check: SSH PAM Enabled (5.1.19)

Ensures PAM (Pluggable Authentication Modules) is enabled for SSH.
PAM provides flexible authentication and session management.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHPAMEnabledCheck(BaseCheck):
    """Check SSH PAM configuration."""

    id = "ssh_pam_enabled"
    name = "SSH PAM Enabled"
    description = (
        "Verifies that PAM (Pluggable Authentication Modules) is enabled "
        "for SSH to provide proper authentication and session management"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for UsePAM setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "use_pam": None,
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

                        match = re.match(r"^UsePAM\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["use_pam"] = value
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

                                match = re.match(r"^UsePAM\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["use_pam"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH PAM check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default on most modern systems is yes
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "UsePAM not explicitly set. Default on most systems is 'yes', "
                    "which enables proper authentication and session management."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["use_pam"] is None:
            # Not explicitly set - default is yes on most systems
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "UsePAM directive not found. Default is 'yes' on most systems, "
                    "which enables proper authentication and session management."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        use_pam_value = config["use_pam"]

        if use_pam_value == "yes":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="UsePAM is enabled - proper authentication and session management",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if use_pam_value == "no":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="UsePAM is disabled - authentication and session management may be bypassed",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    "UsePAM yes\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "PAM provides essential authentication, account, session, and password "
                    "management capabilities. Disabling it can bypass important security "
                    "controls like password policies and account lockout."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"UsePAM has unrecognized value: '{use_pam_value}'",
            remediation=(
                f"Check {config['config_file']} and set:\n"
                "UsePAM yes"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
