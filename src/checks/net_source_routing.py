"""
CIS Audit Check: Source Routed Packets Not Accepted (3.2.1)

Ensures source routed packets are not accepted to prevent routing manipulation.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class SourceRoutingCheck(BaseCheck):
    """Check that source routed packets are not accepted."""

    id = "net_source_routing"
    name = "Source Routed Packets Not Accepted"
    description = (
        "Ensures the system does not accept source routed packets "
        "which could be used to bypass network security controls"
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
    IPV4_ALL_ACCEPT_SOURCE_ROUTE = "net.ipv4.conf.all.accept_source_route"
    IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE = "net.ipv4.conf.default.accept_source_route"
    IPV6_ALL_ACCEPT_SOURCE_ROUTE = "net.ipv6.conf.all.accept_source_route"
    IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE = "net.ipv6.conf.default.accept_source_route"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for accept_source_route settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "ipv4_all_configured": False,
            "ipv4_all_value": None,
            "ipv4_all_config_file": None,
            "ipv4_default_configured": False,
            "ipv4_default_value": None,
            "ipv4_default_config_file": None,
            "ipv6_all_configured": False,
            "ipv6_all_value": None,
            "ipv6_all_config_file": None,
            "ipv6_default_configured": False,
            "ipv6_default_value": None,
            "ipv6_default_config_file": None,
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

                                # IPv4 all
                                if self.IPV4_ALL_ACCEPT_SOURCE_ROUTE in line:
                                    match = re.search(rf'{re.escape(self.IPV4_ALL_ACCEPT_SOURCE_ROUTE)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["ipv4_all_configured"] = True
                                        result["ipv4_all_value"] = int(match.group(1))
                                        result["ipv4_all_config_file"] = f"{path}:{line_num}"

                                # IPv4 default
                                if self.IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE in line:
                                    match = re.search(rf'{re.escape(self.IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["ipv4_default_configured"] = True
                                        result["ipv4_default_value"] = int(match.group(1))
                                        result["ipv4_default_config_file"] = f"{path}:{line_num}"

                                # IPv6 all
                                if self.IPV6_ALL_ACCEPT_SOURCE_ROUTE in line:
                                    match = re.search(rf'{re.escape(self.IPV6_ALL_ACCEPT_SOURCE_ROUTE)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["ipv6_all_configured"] = True
                                        result["ipv6_all_value"] = int(match.group(1))
                                        result["ipv6_all_config_file"] = f"{path}:{line_num}"

                                # IPv6 default
                                if self.IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE in line:
                                    match = re.search(rf'{re.escape(self.IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["ipv6_default_configured"] = True
                                        result["ipv6_default_value"] = int(match.group(1))
                                        result["ipv6_default_config_file"] = f"{path}:{line_num}"

                    except (IOError, OSError):
                        pass

        return result

    def _get_runtime_values(self) -> dict:
        """Get current runtime values from sysctl.

        Returns:
            Dictionary with runtime values
        """
        result = {
            "ipv4_all_runtime": None,
            "ipv4_default_runtime": None,
            "ipv6_all_runtime": None,
            "ipv6_default_runtime": None,
        }

        params = [
            (self.IPV4_ALL_ACCEPT_SOURCE_ROUTE, "ipv4_all_runtime"),
            (self.IPV4_DEFAULT_ACCEPT_SOURCE_ROUTE, "ipv4_default_runtime"),
            (self.IPV6_ALL_ACCEPT_SOURCE_ROUTE, "ipv6_all_runtime"),
            (self.IPV6_DEFAULT_ACCEPT_SOURCE_ROUTE, "ipv6_default_runtime"),
        ]

        for param, key in params:
            try:
                proc = subprocess.run(
                    ["sysctl", "-n", param],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.returncode == 0:
                    result[key] = int(proc.stdout.strip())
            except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the source routing check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_values()

        details = {
            "config": config,
            "runtime": runtime,
        }

        checks = [
            ("ipv4_all", config.get("ipv4_all_value"), runtime.get("ipv4_all_runtime")),
            ("ipv4_default", config.get("ipv4_default_value"), runtime.get("ipv4_default_runtime")),
            ("ipv6_all", config.get("ipv6_all_value"), runtime.get("ipv6_all_runtime")),
            ("ipv6_default", config.get("ipv6_default_value"), runtime.get("ipv6_default_runtime")),
        ]

        issues = []
        for name, cfg_val, run_val in checks:
            if cfg_val != 0:
                issues.append(f"{name} not configured in sysctl files (found: {cfg_val})")
            if run_val != 0:
                issues.append(f"{name} enabled at runtime (value: {run_val})")

        if not issues:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Source routed packets are not accepted for IPv4 and IPv6",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Source routing issues: {'; '.join(issues)}",
            remediation=(
                "Disable source routed packets:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.conf.all.accept_source_route = 0\n"
                "   net.ipv4.conf.default.accept_source_route = 0\n"
                "   net.ipv6.conf.all.accept_source_route = 0\n"
                "   net.ipv6.conf.default.accept_source_route = 0\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl -a | grep accept_source_route"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
