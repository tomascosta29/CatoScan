"""
CIS Audit Check: SSH IgnoreRhosts (5.1.8)

Ensures .rhosts and .shosts files are ignored to prevent
trust-based authentication vulnerabilities.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHIgnoreRhostsCheck(BaseCheck):
    """Check SSH IgnoreRhosts configuration."""

    id = "ssh_ignorerhosts"
    name = "SSH IgnoreRhosts"
    description = (
        "Verifies that .rhosts and .shosts files are ignored "
        "to prevent trust-based authentication vulnerabilities"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for IgnoreRhosts setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "ignorerhosts": None,
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

                        match = re.match(r"^IgnoreRhosts\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["ignorerhosts"] = value
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

                                match = re.match(r"^IgnoreRhosts\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["ignorerhosts"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH IgnoreRhosts check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default IgnoreRhosts is yes
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "IgnoreRhosts not explicitly set. Default is 'yes', "
                    "which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["ignorerhosts"] is None:
            # Not explicitly set - default is yes
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "IgnoreRhosts directive not found. Default is 'yes', "
                    "which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        ignorerhosts = config["ignorerhosts"]

        if ignorerhosts == "yes":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="IgnoreRhosts is enabled - .rhosts and .shosts files are ignored",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if ignorerhosts == "no":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="IgnoreRhosts is disabled - .rhosts and .shosts files are used",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    "IgnoreRhosts yes\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    ".rhosts and .shosts files allow trust-based authentication "
                    "which is vulnerable to spoofing attacks."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"IgnoreRhosts has unrecognized value: '{ignorerhosts}'",
            remediation=(
                f"Check {config['config_file']} and set:\n"
                "IgnoreRhosts yes"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
