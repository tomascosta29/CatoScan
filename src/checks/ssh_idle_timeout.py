"""
CIS Audit Check: SSH Idle Timeout (5.1.16)

Ensures SSH idle timeout is configured via ClientAliveInterval
and ClientAliveCountMax to terminate inactive sessions.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHIdleTimeoutCheck(BaseCheck):
    """Check SSH idle timeout configuration."""

    id = "ssh_idle_timeout"
    name = "SSH Idle Timeout"
    description = (
        "Verifies that SSH idle timeout is configured via "
        "ClientAliveInterval and ClientAliveCountMax to terminate inactive sessions"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    # CIS recommends ClientAliveInterval <= 300 (5 minutes)
    # and ClientAliveCountMax <= 3
    MAX_INTERVAL = 300
    MAX_COUNT = 3

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for idle timeout settings.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "clientaliveinterval": None,
            "clientalivecountmax": None,
            "config_file_interval": None,
            "config_file_count": None,
            "config_line_interval": None,
            "config_line_count": None,
            "files_read": [],
            "all_settings_interval": [],
            "all_settings_count": [],
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

                        # Check ClientAliveInterval
                        match = re.match(r"^ClientAliveInterval\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1)
                            config["all_settings_interval"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            config["clientaliveinterval"] = value
                            config["config_file_interval"] = self.SSHD_CONFIG
                            config["config_line_interval"] = line

                        # Check ClientAliveCountMax
                        match = re.match(r"^ClientAliveCountMax\s+(\S+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1)
                            config["all_settings_count"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            config["clientalivecountmax"] = value
                            config["config_file_count"] = self.SSHD_CONFIG
                            config["config_line_count"] = line

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

                                # Check ClientAliveInterval
                                match = re.match(r"^ClientAliveInterval\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1)
                                    config["all_settings_interval"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    config["clientaliveinterval"] = value
                                    config["config_file_interval"] = str(conf_file)
                                    config["config_line_interval"] = line

                                # Check ClientAliveCountMax
                                match = re.match(r"^ClientAliveCountMax\s+(\S+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1)
                                    config["all_settings_count"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    config["clientalivecountmax"] = value
                                    config["config_file_count"] = str(conf_file)
                                    config["config_line_count"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH idle timeout check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Cannot read SSH configuration files",
                remediation=(
                    "Ensure /etc/ssh/sshd_config exists and is readable.\n"
                    "Then configure idle timeout settings."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        issues = []

        # Check ClientAliveInterval
        interval_ok = False
        if config["clientaliveinterval"] is None:
            issues.append(
                "ClientAliveInterval is not set (default is 0, which disables keepalive)"
            )
        else:
            try:
                interval = int(config["clientaliveinterval"])
                if interval == 0:
                    issues.append("ClientAliveInterval is 0 (keepalive is disabled)")
                elif interval > self.MAX_INTERVAL:
                    issues.append(
                        f"ClientAliveInterval is {interval} seconds "
                        f"(exceeds recommended maximum of {self.MAX_INTERVAL})"
                    )
                else:
                    interval_ok = True
            except ValueError:
                issues.append(
                    f"ClientAliveInterval has invalid value: '{config['clientaliveinterval']}'"
                )

        # Check ClientAliveCountMax
        count_ok = False
        if config["clientalivecountmax"] is None:
            issues.append(
                "ClientAliveCountMax is not set (default is 3, which is acceptable)"
            )
            count_ok = True  # Default is acceptable
        else:
            try:
                count = int(config["clientalivecountmax"])
                if count > self.MAX_COUNT:
                    issues.append(
                        f"ClientAliveCountMax is {count} "
                        f"(exceeds recommended maximum of {self.MAX_COUNT})"
                    )
                else:
                    count_ok = True
            except ValueError:
                issues.append(
                    f"ClientAliveCountMax has invalid value: '{config['clientalivecountmax']}'"
                )

        if issues and not (interval_ok and count_ok):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="; ".join(issues),
                remediation=(
                    "Edit /etc/ssh/sshd_config and set:\n"
                    f"ClientAliveInterval {self.MAX_INTERVAL}\n"
                    f"ClientAliveCountMax {self.MAX_COUNT}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "This will disconnect idle sessions after approximately "
                    f"{self.MAX_INTERVAL * self.MAX_COUNT} seconds of inactivity."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Calculate total timeout
        interval_val = int(config["clientaliveinterval"]) if config["clientaliveinterval"] else 0
        count_val = int(config["clientalivecountmax"]) if config["clientalivecountmax"] else 3
        total_timeout = interval_val * count_val if interval_val > 0 else 0

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"SSH idle timeout is configured: "
                f"ClientAliveInterval={config.get('clientaliveinterval', 'default (0)')}, "
                f"ClientAliveCountMax={config.get('clientalivecountmax', 'default (3)')}"
                f"{f' (total timeout: {total_timeout}s)' if total_timeout > 0 else ''}"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
