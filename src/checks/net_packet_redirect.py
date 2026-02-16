"""
CIS Audit Check: Packet Redirect Sending Disabled (3.1.2)

Ensures packet redirect sending is disabled to prevent MITM attacks.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class PacketRedirectCheck(BaseCheck):
    """Check that packet redirect sending is disabled."""

    id = "net_packet_redirect"
    name = "Packet Redirect Sending Disabled"
    description = (
        "Ensures the system does not send ICMP redirects "
        "which could be used in man-in-the-middle attacks"
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
    ALL_SEND_REDIRECTS = "net.ipv4.conf.all.send_redirects"
    DEFAULT_SEND_REDIRECTS = "net.ipv4.conf.default.send_redirects"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for send_redirects settings.

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

                                # Check all.send_redirects
                                if self.ALL_SEND_REDIRECTS in line:
                                    match = re.search(rf'{re.escape(self.ALL_SEND_REDIRECTS)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["all_configured"] = True
                                        result["all_value"] = int(match.group(1))
                                        result["all_config_file"] = f"{path}:{line_num}"

                                # Check default.send_redirects
                                if self.DEFAULT_SEND_REDIRECTS in line:
                                    match = re.search(rf'{re.escape(self.DEFAULT_SEND_REDIRECTS)}\s*=\s*(\d+)', line)
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

        # Check all.send_redirects
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.ALL_SEND_REDIRECTS],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["all_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        # Check default.send_redirects
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.DEFAULT_SEND_REDIRECTS],
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
        """Execute the packet redirect check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_values()

        details = {
            "config": config,
            "runtime": runtime,
        }

        all_config_ok = config.get("all_value") == 0
        default_config_ok = config.get("default_value") == 0
        all_runtime_ok = runtime.get("all_runtime") == 0
        default_runtime_ok = runtime.get("default_runtime") == 0

        # Determine overall status
        all_ok = all_config_ok and default_config_ok and all_runtime_ok and default_runtime_ok

        if all_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Packet redirect sending is disabled",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not all_config_ok:
            issues.append(f"all.send_redirects not configured in sysctl files (found: {config.get('all_value')})")
        if not default_config_ok:
            issues.append(f"default.send_redirects not configured in sysctl files (found: {config.get('default_value')})")
        if not all_runtime_ok:
            issues.append(f"all.send_redirects enabled at runtime (value: {runtime.get('all_runtime')})")
        if not default_runtime_ok:
            issues.append(f"default.send_redirects enabled at runtime (value: {runtime.get('default_runtime')})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Packet redirect issues: {'; '.join(issues)}",
            remediation=(
                "Disable packet redirect sending:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.conf.all.send_redirects = 0\n"
                "   net.ipv4.conf.default.send_redirects = 0\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
