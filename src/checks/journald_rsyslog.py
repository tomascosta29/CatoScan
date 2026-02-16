"""
CIS Audit Check: Journald Sends Logs to rsyslog (4.2.2.1)

Ensures systemd-journald is configured to send logs to rsyslog.
"""

import os
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class JournaldRsyslogCheck(BaseCheck):
    """Check if journald is configured to send logs to rsyslog."""

    id = "journald_rsyslog"
    name = "Journald Sends Logs to rsyslog"
    description = (
        "Verifies that systemd-journald is configured to forward log messages "
        "to rsyslog for centralized logging"
    )
    severity = Severity.MEDIUM
    requires_root = True

    CONFIG_PATH = "/etc/systemd/journald.conf"

    def _read_journald_config(self) -> dict:
        """Read journald configuration file.

        Returns:
            Dictionary with configuration settings
        """
        result = {
            "config_exists": False,
            "config_path": self.CONFIG_PATH,
            "forward_to_syslog": None,
            "max_file_size": None,
            "config_lines": [],
        }

        config_file = Path(self.CONFIG_PATH)
        if config_file.exists():
            result["config_exists"] = True
            try:
                with open(config_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        result["config_lines"].append(line)
                        
                        if not line or line.startswith("#"):
                            continue
                        
                        # Parse ForwardToSyslog setting
                        if line.startswith("ForwardToSyslog="):
                            value = line.split("=", 1)[1].strip()
                            result["forward_to_syslog"] = value.lower()
                        
                        # Parse SystemMaxFileSize
                        if line.startswith("SystemMaxFileSize="):
                            result["max_file_size"] = line.split("=", 1)[1].strip()
                            
            except (PermissionError, OSError) as e:
                result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the journald rsyslog check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_journald_config()

        details = {
            "config": config,
        }

        # Check if config file exists
        if not config["config_exists"]:
            # Default behavior: journald does forward to syslog by default
            # if rsyslog is installed
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald.conf not found, using defaults (ForwardToSyslog=yes by default)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        forward_value = config.get("forward_to_syslog")

        # If not explicitly set, default is "yes"
        if forward_value is None:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="ForwardToSyslog not explicitly set, using default (yes)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if forward_value == "yes":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald is configured to forward logs to rsyslog",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"journald ForwardToSyslog is set to '{forward_value}' (expected: yes)",
            remediation=(
                "Configure journald to forward logs to rsyslog:\n"
                "1. Edit /etc/systemd/journald.conf:\n"
                "   sudo nano /etc/systemd/journald.conf\n"
                "2. Add or modify in the [Journal] section:\n"
                "   ForwardToSyslog=yes\n"
                "3. Restart journald:\n"
                "   sudo systemctl restart systemd-journald\n"
                "4. Verify rsyslog is receiving logs:\n"
                "   sudo tail -f /var/log/messages"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
