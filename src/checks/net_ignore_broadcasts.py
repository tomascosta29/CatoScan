"""
CIS Audit Check: Broadcast ICMP Requests Ignored (3.2.5)

Ensures broadcast ICMP requests are ignored to prevent Smurf attacks.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class IgnoreBroadcastsCheck(BaseCheck):
    """Check that broadcast ICMP requests are ignored."""

    id = "net_ignore_broadcasts"
    name = "Broadcast ICMP Requests Ignored"
    description = (
        "Ensures the system ignores broadcast ICMP echo requests "
        "to prevent participation in Smurf attacks"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Sysctl configuration files
    SYSCTL_PATHS = [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/*.conf",
        "/usr/lib/sysctl.d/*.conf",
        "/run/sysctl.d/*.conf",
    ]

    # Parameter to check
    ICMP_ECHO_IGNORE_BROADCASTS = "net.ipv4.icmp_echo_ignore_broadcasts"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for icmp_echo_ignore_broadcasts settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "configured": False,
            "value": None,
            "config_file": None,
            "config_files_checked": [],
        }

        for pattern in self.SYSCTL_PATHS:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    result["config_files_checked"].append(path)
                    try:
                        with open(path, "r") as f:
                            for line_num, line in enumerate(f, 1):
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                # Check icmp_echo_ignore_broadcasts
                                if self.ICMP_ECHO_IGNORE_BROADCASTS in line:
                                    match = re.search(rf'{re.escape(self.ICMP_ECHO_IGNORE_BROADCASTS)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["configured"] = True
                                        result["value"] = int(match.group(1))
                                        result["config_file"] = f"{path}:{line_num}"

                    except (IOError, OSError):
                        pass

        return result

    def _get_runtime_value(self) -> int | None:
        """Get current runtime value from sysctl.

        Returns:
            Runtime value or None if unavailable
        """
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.ICMP_ECHO_IGNORE_BROADCASTS],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                return int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
        return None

    def run(self) -> CheckResult:
        """Execute the ignore broadcasts check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_value()

        details = {
            "config": config,
            "runtime_value": runtime,
        }

        config_ok = config.get("value") == 1
        runtime_ok = runtime == 1

        # Determine overall status
        all_ok = config_ok and runtime_ok

        if all_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Broadcast ICMP requests are ignored",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not config_ok:
            issues.append(f"icmp_echo_ignore_broadcasts not configured to 1 (found: {config.get('value')})")
        if not runtime_ok:
            issues.append(f"icmp_echo_ignore_broadcasts not enabled at runtime (value: {runtime})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Broadcast ignore issues: {'; '.join(issues)}",
            remediation=(
                "Ignore broadcast ICMP requests:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.icmp_echo_ignore_broadcasts"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
