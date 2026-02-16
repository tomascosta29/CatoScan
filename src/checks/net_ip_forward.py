"""
CIS Audit Check: IP Forwarding Disabled (3.1.1)

Ensures IP forwarding is disabled in sysctl configuration and runtime.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class IPForwardCheck(BaseCheck):
    """Check that IP forwarding is disabled."""

    id = "net_ip_forward"
    name = "IP Forwarding Disabled"
    description = (
        "Ensures IP forwarding is disabled in kernel parameters "
        "to prevent the system from acting as a router"
    )
    severity = Severity.HIGH
    requires_root = True

    # Sysctl configuration files
    SYSCTL_PATHS = [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/*.conf",
        "/usr/lib/sysctl.d/*.conf",
        "/run/sysctl.d/*.conf",
    ]

    # Parameters to check
    IPV4_PARAM = "net.ipv4.ip_forward"
    IPV6_PARAM = "net.ipv6.conf.all.forwarding"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for IP forwarding settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "ipv4_configured": False,
            "ipv4_value": None,
            "ipv4_config_file": None,
            "ipv6_configured": False,
            "ipv6_value": None,
            "ipv6_config_file": None,
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

                                # Check IPv4 forwarding
                                if self.IPV4_PARAM in line:
                                    match = re.search(rf'{re.escape(self.IPV4_PARAM)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["ipv4_configured"] = True
                                        result["ipv4_value"] = int(match.group(1))
                                        result["ipv4_config_file"] = f"{path}:{line_num}"

                                # Check IPv6 forwarding
                                if self.IPV6_PARAM in line:
                                    match = re.search(rf'{re.escape(self.IPV6_PARAM)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["ipv6_configured"] = True
                                        result["ipv6_value"] = int(match.group(1))
                                        result["ipv6_config_file"] = f"{path}:{line_num}"

                    except (IOError, OSError):
                        pass

        return result

    def _get_runtime_values(self) -> dict:
        """Get current runtime values from sysctl.

        Returns:
            Dictionary with runtime values
        """
        result = {
            "ipv4_runtime": None,
            "ipv6_runtime": None,
        }

        # Check IPv4 forwarding
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.IPV4_PARAM],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["ipv4_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        # Check IPv6 forwarding
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.IPV6_PARAM],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["ipv6_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the IP forwarding check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_values()

        details = {
            "config": config,
            "runtime": runtime,
        }

        ipv4_config_ok = config.get("ipv4_value") == 0
        ipv6_config_ok = config.get("ipv6_value") == 0
        ipv4_runtime_ok = runtime.get("ipv4_runtime") == 0
        ipv6_runtime_ok = runtime.get("ipv6_runtime") == 0

        # Determine overall status
        all_ok = ipv4_config_ok and ipv6_config_ok and ipv4_runtime_ok and ipv6_runtime_ok

        if all_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="IP forwarding is disabled for both IPv4 and IPv6",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not ipv4_config_ok:
            issues.append(f"IPv4 not configured in sysctl files (found: {config.get('ipv4_value')})")
        if not ipv6_config_ok:
            issues.append(f"IPv6 not configured in sysctl files (found: {config.get('ipv6_value')})")
        if not ipv4_runtime_ok:
            issues.append(f"IPv4 forwarding enabled at runtime (value: {runtime.get('ipv4_runtime')})")
        if not ipv6_runtime_ok:
            issues.append(f"IPv6 forwarding enabled at runtime (value: {runtime.get('ipv6_runtime')})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"IP forwarding issues: {'; '.join(issues)}",
            remediation=(
                "Disable IP forwarding:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.ip_forward = 0\n"
                "   net.ipv6.conf.all.forwarding = 0\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
