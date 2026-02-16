"""
CIS Audit Check: SSH X11 Forwarding (5.1.6)

Ensures X11 forwarding is disabled unless explicitly required.
X11 forwarding can expose the system to security risks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHX11Check(BaseCheck):
    """Check SSH X11 forwarding configuration."""

    id = "ssh_x11"
    name = "SSH X11 Forwarding"
    description = (
        "Verifies that X11 forwarding is disabled to prevent "
        "potential security risks from X11 protocol vulnerabilities"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for X11Forwarding setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "x11_forwarding": None,
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

                        match = re.match(r"^X11Forwarding\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).lower()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["x11_forwarding"] = value
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

                                match = re.match(r"^X11Forwarding\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).lower()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["x11_forwarding"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH X11 forwarding check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default X11Forwarding is no
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "X11Forwarding not explicitly set. Default is 'no', "
                    "which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["x11_forwarding"] is None:
            # Not explicitly set - default is no
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "X11Forwarding directive not found. Default is 'no', "
                    "which is secure."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        x11_value = config["x11_forwarding"]

        if x11_value == "no":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="X11Forwarding is disabled - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if x11_value == "yes":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="X11Forwarding is enabled - potential security risk",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    "X11Forwarding no\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "X11 forwarding can expose the system to security vulnerabilities. "
                    "Only enable if explicitly required for specific use cases."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Unknown value
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"X11Forwarding has unrecognized value: '{x11_value}'",
            remediation=(
                f"Check {config['config_file']} and set:\n"
                "X11Forwarding no"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
