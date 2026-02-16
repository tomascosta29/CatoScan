"""
CIS Audit Check: Remote Logging Configuration

Checks if remote logging is configured in rsyslog.
Note: Remote logging is informational - it may not be required for all systems.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class RemoteLoggingCheck(BaseCheck):
    """Check for remote logging configuration in rsyslog."""

    id = "logging_remote"
    name = "Remote Logging Configuration"
    description = (
        "Checks if remote logging is configured in rsyslog. "
        "Remote logging helps centralize logs for security monitoring. "
        "Note: This is informational - remote logging may not be required for all systems."
    )
    severity = Severity.LOW
    requires_root = True

    RSYSLOG_CONF = "/etc/rsyslog.conf"
    RSYSLOG_D_DIR = "/etc/rsyslog.d"

    # Patterns for remote logging configuration
    # @server = UDP, @@server = TCP
    REMOTE_PATTERNS = [
        r"^\s*[@]{1,2}[^#\s]+",  # @server or @@server
        r"^\s*\*\.\*\s+[@]{1,2}[^#\s]+",  # *.* @server
        r"Action\s+\(\s*type=\"omfwd\"",  # Modern rsyslog action format
    ]

    def _check_file_for_remote(self, file_path: str) -> list[dict]:
        """Check a single file for remote logging configuration.

        Args:
            file_path: Path to the file to check

        Returns:
            List of remote logging configurations found
        """
        configs = []

        try:
            with open(file_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.rstrip()

                    # Skip comments and empty lines
                    if not line.strip() or line.strip().startswith("#"):
                        continue

                    # Check for remote logging patterns
                    for pattern in self.REMOTE_PATTERNS:
                        if re.search(pattern, line):
                            configs.append({
                                "file": file_path,
                                "line": line_num,
                                "config": line.strip(),
                            })
                            break

        except (IOError, OSError):
            pass

        return configs

    def _find_remote_configs(self) -> list[dict]:
        """Find all remote logging configurations.

        Returns:
            List of remote logging configurations found
        """
        configs = []

        # Check main rsyslog.conf
        if os.path.exists(self.RSYSLOG_CONF):
            configs.extend(self._check_file_for_remote(self.RSYSLOG_CONF))

        # Check rsyslog.d directory
        if os.path.isdir(self.RSYSLOG_D_DIR):
            try:
                for conf_file in sorted(Path(self.RSYSLOG_D_DIR).glob("*.conf")):
                    configs.extend(self._check_file_for_remote(str(conf_file)))
            except (IOError, OSError):
                pass

        return configs

    def run(self) -> CheckResult:
        """Execute the remote logging check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "rsyslog_conf_exists": os.path.exists(self.RSYSLOG_CONF),
            "rsyslog_d_exists": os.path.isdir(self.RSYSLOG_D_DIR),
            "remote_configs": [],
        }

        # Find remote logging configurations
        remote_configs = self._find_remote_configs()
        details["remote_configs"] = remote_configs

        if remote_configs:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Remote logging is configured ({len(remote_configs)} configuration(s) found)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # No remote logging configured - this is informational
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="Remote logging is not configured in rsyslog",
            remediation=(
                "Consider configuring remote logging for centralized log management:\n"
                "1. Edit /etc/rsyslog.conf or create a file in /etc/rsyslog.d/\n"
                "2. Add remote logging configuration:\n"
                "   # For UDP (less reliable, lower overhead):\n"
                "   *.* @logserver.example.com:514\n\n"
                "   # For TCP (more reliable, higher overhead):\n"
                "   *.* @@logserver.example.com:514\n\n"
                "   # Or using modern action format:\n"
                "   action(type=\"omfwd\" target=\"logserver.example.com\" "
                "port=\"514\" protocol=\"tcp\")\n"
                "3. Restart rsyslog: systemctl restart rsyslog\n\n"
                "Note: Remote logging is optional but recommended for production environments "
                "and systems requiring centralized security monitoring."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
