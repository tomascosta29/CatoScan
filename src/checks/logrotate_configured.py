"""
CIS Audit Check: Logrotate Configured (4.3.2)

Ensures that logrotate is properly configured to rotate logs
on a regular basis and retain them for an appropriate period.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class LogrotateConfiguredCheck(BaseCheck):
    """Check if logrotate is properly configured."""

    id = "logrotate_configured"
    name = "Logrotate Configured"
    description = (
        "Verifies that logrotate is properly configured to rotate logs "
        "and retain them for an appropriate period"
    )
    severity = Severity.MEDIUM
    requires_root = True

    LOGROTATE_CONF = "/etc/logrotate.conf"
    LOGROTATE_D_DIR = "/etc/logrotate.d"

    def _check_main_config(self) -> dict:
        """Check /etc/logrotate.conf for basic configuration.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "file_exists": False,
            "readable": False,
            "rotate_configured": False,
            "rotate_weekly": False,
            "rotate_daily": False,
            "rotate_monthly": False,
            "rotate_value": None,
            "compress": False,
            "missingok": False,
            "notifempty": False,
            "create": False,
            "dateext": False,
            "include_logrotate_d": False,
        }

        path = Path(self.LOGROTATE_CONF)
        if not path.exists():
            return result

        result["file_exists"] = True

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result["readable"] = True
            result["content"] = content

            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Check rotation period
                if re.match(r'^weekly\b', line, re.IGNORECASE):
                    result["rotate_weekly"] = True
                elif re.match(r'^daily\b', line, re.IGNORECASE):
                    result["rotate_daily"] = True
                elif re.match(r'^monthly\b', line, re.IGNORECASE):
                    result["rotate_monthly"] = True

                # Check rotate value (number of rotations to keep)
                match = re.match(r'^rotate\s+(\d+)', line, re.IGNORECASE)
                if match:
                    result["rotate_configured"] = True
                    result["rotate_value"] = int(match.group(1))

                # Check other options
                if re.match(r'^compress\b', line, re.IGNORECASE):
                    result["compress"] = True
                if re.match(r'^missingok\b', line, re.IGNORECASE):
                    result["missingok"] = True
                if re.match(r'^notifempty\b', line, re.IGNORECASE):
                    result["notifempty"] = True
                if re.match(r'^create\b', line, re.IGNORECASE):
                    result["create"] = True
                if re.match(r'^dateext\b', line, re.IGNORECASE):
                    result["dateext"] = True
                if re.match(r'^include\s+/etc/logrotate\.d', line, re.IGNORECASE):
                    result["include_logrotate_d"] = True

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def _check_logrotate_d(self) -> dict:
        """Check /etc/logrotate.d for additional configurations.

        Returns:
            Dictionary with findings
        """
        result = {
            "dir_exists": False,
            "config_files": [],
            "total_configs": 0,
        }

        path = Path(self.LOGROTATE_D_DIR)
        if not path.exists() or not path.is_dir():
            return result

        result["dir_exists"] = True

        try:
            for config_file in path.iterdir():
                if config_file.is_file() and not config_file.name.startswith("."):
                    result["config_files"].append(config_file.name)
                    result["total_configs"] += 1

        except (IOError, OSError):
            pass

        return result

    def _check_cron_job(self) -> dict:
        """Check if logrotate has a cron job configured.

        Returns:
            Dictionary with cron findings
        """
        result = {
            "cron_daily_exists": False,
            "cron_hourly_exists": False,
            "systemd_timer_exists": False,
        }

        # Check for cron.daily
        cron_daily = Path("/etc/cron.daily/logrotate")
        if cron_daily.exists():
            result["cron_daily_exists"] = True

        # Check for cron.hourly
        cron_hourly = Path("/etc/cron.hourly/logrotate")
        if cron_hourly.exists():
            result["cron_hourly_exists"] = True

        # Check for systemd timer
        timer_paths = [
            "/etc/systemd/system/logrotate.timer",
            "/usr/lib/systemd/system/logrotate.timer",
            "/lib/systemd/system/logrotate.timer",
        ]
        for timer_path in timer_paths:
            if Path(timer_path).exists():
                result["systemd_timer_exists"] = True
                result["timer_path"] = timer_path
                break

        return result

    def run(self) -> CheckResult:
        """Execute the logrotate configured check.

        Returns:
            CheckResult with the outcome of the check
        """
        main_config = self._check_main_config()
        logrotate_d = self._check_logrotate_d()
        cron_config = self._check_cron_job()

        details = {
            "main_config": main_config,
            "logrotate_d": logrotate_d,
            "cron_config": cron_config,
        }

        # Check for errors
        if "error" in main_config:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Error reading {self.LOGROTATE_CONF}: {main_config['error']}",
                remediation="Check file permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if main config exists
        if not main_config["file_exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.LOGROTATE_CONF} does not exist",
                remediation=(
                    f"Create {self.LOGROTATE_CONF} with proper configuration:\n\n"
                    "Example configuration:\n"
                    "  weekly\n"
                    "  rotate 4\n"
                    "  create\n"
                    "  dateext\n"
                    "  compress\n"
                    "  include /etc/logrotate.d\n\n"
                    "  /var/log/wtmp {\n"
                    "      monthly\n"
                    "      create 0664 root utmp\n"
                    "      minsize 1M\n"
                    "      rotate 1\n"
                    "  }\n\n"
                    "  /var/log/btmp {\n"
                    "      missingok\n"
                    "      monthly\n"
                    "      create 0600 root utmp\n"
                    "      rotate 1\n"
                    "  }"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        recommendations = []

        # Check rotation period
        if not (main_config["rotate_weekly"] or main_config["rotate_daily"] or main_config["rotate_monthly"]):
            issues.append("no rotation period configured (weekly/daily/monthly)")
            recommendations.append("Add 'weekly' to /etc/logrotate.conf")

        # Check rotate value
        if not main_config["rotate_configured"]:
            issues.append("rotate value not configured")
            recommendations.append("Add 'rotate 4' to /etc/logrotate.conf (keeps 4 weeks of logs)")
        elif main_config["rotate_value"] is not None and main_config["rotate_value"] < 4:
            issues.append(f"rotate value is {main_config['rotate_value']} (recommended: at least 4)")
            recommendations.append("Set 'rotate 4' or higher in /etc/logrotate.conf")

        # Check for scheduling mechanism
        has_scheduler = (
            cron_config["cron_daily_exists"] or
            cron_config["cron_hourly_exists"] or
            cron_config["systemd_timer_exists"]
        )
        if not has_scheduler:
            issues.append("no cron job or systemd timer found for logrotate")
            recommendations.append("Ensure logrotate is scheduled via cron or systemd timer")

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Logrotate configuration issues: {'; '.join(issues)}",
                remediation=(
                    "Configure logrotate properly:\n\n"
                    + "\n".join(recommendations) +
                    "\n\nExample /etc/logrotate.conf:\n"
                    "  # Rotate log files weekly\n"
                    "  weekly\n\n"
                    "  # Keep 4 weeks worth of backlogs\n"
                    "  rotate 4\n\n"
                    "  # Create new (empty) log files after rotating old ones\n"
                    "  create\n\n"
                    "  # Use date as a suffix of the rotated file\n"
                    "  dateext\n\n"
                    "  # Compress rotated files\n"
                    "  compress\n\n"
                    "  # Packages drop log rotation info into this directory\n"
                    "  include /etc/logrotate.d\n\n"
                    "CIS Benchmark: 4.3.2 - Ensure logrotate is configured"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Logrotate is properly configured",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
