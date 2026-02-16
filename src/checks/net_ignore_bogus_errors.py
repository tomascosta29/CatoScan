"""
CIS Audit Check: Bogus ICMP Responses Ignored (3.2.6)

Ensures bogus ICMP error responses are ignored to prevent log flooding.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class IgnoreBogusErrorsCheck(BaseCheck):
    """Check that bogus ICMP error responses are ignored."""

    id = "net_ignore_bogus_errors"
    name = "Bogus ICMP Responses Ignored"
    description = (
        "Ensures the system ignores bogus ICMP error responses "
        "to prevent unnecessary log entries"
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
    ICMP_IGNORE_BOGUS_ERROR_RESPONSES = "net.ipv4.icmp_ignore_bogus_error_responses"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for icmp_ignore_bogus_error_responses settings.

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

                                # Check icmp_ignore_bogus_error_responses
                                if self.ICMP_IGNORE_BOGUS_ERROR_RESPONSES in line:
                                    match = re.search(rf'{re.escape(self.ICMP_IGNORE_BOGUS_ERROR_RESPONSES)}\s*=\s*(\d+)', line)
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
                ["sysctl", "-n", self.ICMP_IGNORE_BOGUS_ERROR_RESPONSES],
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
        """Execute the ignore bogus errors check.

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
                message="Bogus ICMP error responses are ignored",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not config_ok:
            issues.append(f"icmp_ignore_bogus_error_responses not configured to 1 (found: {config.get('value')})")
        if not runtime_ok:
            issues.append(f"icmp_ignore_bogus_error_responses not enabled at runtime (value: {runtime})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Bogus error ignore issues: {'; '.join(issues)}",
            remediation=(
                "Ignore bogus ICMP error responses:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.icmp_ignore_bogus_error_responses = 1\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.icmp_ignore_bogus_error_responses"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
