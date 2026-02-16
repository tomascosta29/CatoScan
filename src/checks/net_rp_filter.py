"""
CIS Audit Check: Reverse Path Filtering Enabled (3.2.7)

Ensures reverse path filtering is enabled to prevent IP spoofing.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class RPFilterCheck(BaseCheck):
    """Check that reverse path filtering is enabled."""

    id = "net_rp_filter"
    name = "Reverse Path Filtering Enabled"
    description = (
        "Ensures reverse path filtering is enabled to validate "
        "that incoming packets have a valid source address"
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

    # Parameters to check
    ALL_RP_FILTER = "net.ipv4.conf.all.rp_filter"
    DEFAULT_RP_FILTER = "net.ipv4.conf.default.rp_filter"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for rp_filter settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "all_configured": False,
            "all_value": None,
            "all_config_file": None,
            "default_configured": False,
            "default_value": None,
            "default_config_file": None,
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

                                # Check all.rp_filter
                                if self.ALL_RP_FILTER in line:
                                    match = re.search(rf'{re.escape(self.ALL_RP_FILTER)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["all_configured"] = True
                                        result["all_value"] = int(match.group(1))
                                        result["all_config_file"] = f"{path}:{line_num}"

                                # Check default.rp_filter
                                if self.DEFAULT_RP_FILTER in line:
                                    match = re.search(rf'{re.escape(self.DEFAULT_RP_FILTER)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["default_configured"] = True
                                        result["default_value"] = int(match.group(1))
                                        result["default_config_file"] = f"{path}:{line_num}"

                    except (IOError, OSError):
                        pass

        return result

    def _get_runtime_values(self) -> dict:
        """Get current runtime values from sysctl.

        Returns:
            Dictionary with runtime values
        """
        result = {
            "all_runtime": None,
            "default_runtime": None,
        }

        # Check all.rp_filter
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.ALL_RP_FILTER],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["all_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        # Check default.rp_filter
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.DEFAULT_RP_FILTER],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["default_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the reverse path filtering check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_values()

        details = {
            "config": config,
            "runtime": runtime,
        }

        # rp_filter value of 1 = strict mode (recommended)
        # rp_filter value of 2 = loose mode (acceptable but not ideal)
        all_config_ok = config.get("all_value") == 1
        default_config_ok = config.get("default_value") == 1
        all_runtime_ok = runtime.get("all_runtime") == 1
        default_runtime_ok = runtime.get("default_runtime") == 1

        # Also accept value of 2 (loose mode) as passing, but warn
        all_runtime_loose = runtime.get("all_runtime") == 2
        default_runtime_loose = runtime.get("default_runtime") == 2

        # Determine overall status
        all_ok = all_config_ok and default_config_ok and (all_runtime_ok or all_runtime_loose) and (default_runtime_ok or default_runtime_loose)

        if all_ok:
            mode_str = "strict" if (all_runtime_ok and default_runtime_ok) else "loose"
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Reverse path filtering is enabled ({mode_str} mode)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not all_config_ok:
            issues.append(f"all.rp_filter not configured to 1 (found: {config.get('all_value')})")
        if not default_config_ok:
            issues.append(f"default.rp_filter not configured to 1 (found: {config.get('default_value')})")
        if not all_runtime_ok and not all_runtime_loose:
            issues.append(f"all.rp_filter not enabled at runtime (value: {runtime.get('all_runtime')})")
        if not default_runtime_ok and not default_runtime_loose:
            issues.append(f"default.rp_filter not enabled at runtime (value: {runtime.get('default_runtime')})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Reverse path filtering issues: {'; '.join(issues)}",
            remediation=(
                "Enable reverse path filtering:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.conf.all.rp_filter = 1\n"
                "   net.ipv4.conf.default.rp_filter = 1\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter\n"
                "Note: Value 1 = strict mode (recommended), Value 2 = loose mode"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
