"""
CIS Audit Check: AIDE Cron Job

Checks if AIDE has a cron job configured for regular execution (CIS 1.2.2).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AIDECronCheck(BaseCheck):
    """Check if AIDE has a cron job configured."""

    id = "fs_aide_cron"
    name = "AIDE Cron Job"
    description = (
        "Verifies that AIDE has a cron job or systemd timer configured "
        "to run file integrity checks on a regular schedule"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Cron file locations to check
    CRON_PATHS = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.hourly",
        "/var/spool/cron",
    ]

    # Systemd timer names for AIDE
    SYSTEMD_TIMERS = [
        "aide-check.timer",
        "aide.timer",
    ]

    def _check_cron_files(self) -> list[dict]:
        """Check cron files for AIDE entries.

        Returns:
            List of found AIDE cron configurations
        """
        configs = []

        # Check /etc/crontab
        crontab = Path("/etc/crontab")
        if crontab.exists():
            try:
                with open(crontab, "r") as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        if "aide" in line.lower():
                            configs.append({
                                "file": str(crontab),
                                "line_number": line_num,
                                "line": line,
                            })
            except (PermissionError, OSError):
                pass

        # Check /etc/cron.d directory
        cron_d = Path("/etc/cron.d")
        if cron_d.exists() and cron_d.is_dir():
            try:
                for cron_file in cron_d.iterdir():
                    if cron_file.is_file():
                        try:
                            with open(cron_file, "r") as f:
                                for line_num, line in enumerate(f, 1):
                                    line = line.strip()
                                    if line.startswith("#") or not line:
                                        continue
                                    if "aide" in line.lower():
                                        configs.append({
                                            "file": str(cron_file),
                                            "line_number": line_num,
                                            "line": line,
                                        })
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass

        # Check /etc/cron.daily, /etc/cron.weekly, /etc/cron.hourly
        for cron_dir_name in ["cron.daily", "cron.weekly", "cron.hourly"]:
            cron_dir = Path(f"/etc/{cron_dir_name}")
            if cron_dir.exists() and cron_dir.is_dir():
                try:
                    for script in cron_dir.iterdir():
                        if script.is_file():
                            # Check filename for aide
                            if "aide" in script.name.lower():
                                configs.append({
                                    "file": str(script),
                                    "type": f"{cron_dir_name} script",
                                })
                            else:
                                # Check file content for aide
                                try:
                                    with open(script, "r") as f:
                                        content = f.read()
                                        if "aide" in content.lower():
                                            configs.append({
                                                "file": str(script),
                                                "type": f"{cron_dir_name} script",
                                                "contains_aide": True,
                                            })
                                except (PermissionError, OSError):
                                    pass
                except (PermissionError, OSError):
                    pass

        return configs

    def _check_systemd_timers(self) -> list[dict]:
        """Check for AIDE systemd timers.

        Returns:
            List of found AIDE timer configurations
        """
        timers = []

        for timer_name in self.SYSTEMD_TIMERS:
            try:
                # Check if timer exists and is enabled
                status_result = subprocess.run(
                    ["systemctl", "is-enabled", timer_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                # Check if timer is active
                active_result = subprocess.run(
                    ["systemctl", "is-active", timer_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                # Only add if the timer exists (not "could not be found")
                if "could not be found" not in status_result.stderr:
                    timers.append({
                        "timer": timer_name,
                        "enabled": status_result.returncode == 0,
                        "active": active_result.returncode == 0,
                    })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return timers

    def _check_user_crontabs(self) -> list[dict]:
        """Check user crontabs for AIDE entries.

        Returns:
            List of found AIDE user cron configurations
        """
        configs = []

        # Check /var/spool/cron for user crontabs
        spool_cron = Path("/var/spool/cron")
        if spool_cron.exists() and spool_cron.is_dir():
            try:
                for user_cron in spool_cron.iterdir():
                    if user_cron.is_file():
                        try:
                            with open(user_cron, "r") as f:
                                for line_num, line in enumerate(f, 1):
                                    line = line.strip()
                                    if line.startswith("#") or not line:
                                        continue
                                    if "aide" in line.lower():
                                        configs.append({
                                            "file": str(user_cron),
                                            "user": user_cron.name,
                                            "line_number": line_num,
                                            "line": line,
                                        })
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass

        return configs

    def run(self) -> CheckResult:
        """Execute the AIDE cron job check.

        Returns:
            CheckResult with the outcome of the check
        """
        cron_configs = self._check_cron_files()
        systemd_timers = self._check_systemd_timers()
        user_crontabs = self._check_user_crontabs()

        # Check if any enabled timers exist
        enabled_timers = [t for t in systemd_timers if t.get("enabled", False)]

        details = {
            "cron_configs": cron_configs,
            "systemd_timers": systemd_timers,
            "user_crontabs": user_crontabs,
        }

        # Determine result
        if cron_configs or enabled_timers:
            message_parts = []
            if cron_configs:
                message_parts.append(f"{len(cron_configs)} cron configuration(s) found")
            if enabled_timers:
                timer_names = [t["timer"] for t in enabled_timers]
                message_parts.append(f"systemd timer(s) enabled: {', '.join(timer_names)}")

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="; ".join(message_parts),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = ["No AIDE cron job or systemd timer configured"]

        # Build remediation
        remediation_parts = [
            "Configure AIDE to run regularly via cron or systemd timer:",
            "",
            "Option 1 - Daily cron script:",
            "   sudo tee /etc/cron.daily/aide-check << 'EOF'",
            "   #!/bin/bash",
            "   /usr/sbin/aide --check | mail -s \"AIDE Check $(hostname)\" root",
            "   EOF",
            "   sudo chmod +x /etc/cron.daily/aide-check",
            "",
            "Option 2 - Weekly cron script (less resource intensive):",
            "   sudo tee /etc/cron.weekly/aide-check << 'EOF'",
            "   #!/bin/bash",
            "   /usr/sbin/aide --check | mail -s \"AIDE Check $(hostname)\" root",
            "   EOF",
            "   sudo chmod +x /etc/cron.weekly/aide-check",
            "",
            "Option 3 - Custom cron schedule (e.g., daily at 3 AM):",
            "   sudo tee /etc/cron.d/aide << 'EOF'",
            "   0 3 * * * root /usr/sbin/aide --check | mail -s \"AIDE Check $(hostname)\" root",
            "   EOF",
            "",
            "4. Verify the cron job is configured:",
            "   ls -la /etc/cron.daily/aide-check",
            "   # or",
            "   cat /etc/cron.d/aide",
            "",
            "Note: AIDE checks can be resource-intensive. Schedule during off-peak hours.",
            "      Consider the trade-off between security (more frequent checks) and performance.",
        ]

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
