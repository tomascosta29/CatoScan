"""
CIS Audit Check: ICMP Redirects Not Accepted (3.2.2)

Ensures ICMP redirect acceptance is disabled to prevent routing table manipulation.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class ICMPRedirectsCheck(BaseCheck):
    """Check that ICMP redirects are not accepted."""

    id = "net_icmp_redirects"
    name = "ICMP Redirects Not Accepted"
    description = (
        "Ensures the system does not accept ICMP redirect messages "
        "which could be used to manipulate routing tables"
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
    ALL_ACCEPT_REDIRECTS = "net.ipv4.conf.all.accept_redirects"
    DEFAULT_ACCEPT_REDIRECTS = "net.ipv4.conf.default.accept_redirects"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for accept_redirects settings.

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

                                # Check all.accept_redirects
                                if self.ALL_ACCEPT_REDIRECTS in line:
                                    match = re.search(rf'{re.escape(self.ALL_ACCEPT_REDIRECTS)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["all_configured"] = True
                                        result["all_value"] = int(match.group(1))
                                        result["all_config_file"] = f"{path}:{line_num}"

                                # Check default.accept_redirects
                                if self.DEFAULT_ACCEPT_REDIRECTS in line:
                                    match = re.search(rf'{re.escape(self.DEFAULT_ACCEPT_REDIRECTS)}\s*=\s*(\d+)', line)
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

        # Check all.accept_redirects
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.ALL_ACCEPT_REDIRECTS],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["all_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        # Check default.accept_redirects
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.DEFAULT_ACCEPT_REDIRECTS],
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
        """Execute the ICMP redirects check.

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
                message="ICMP redirects are not accepted",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not all_config_ok:
            issues.append(f"all.accept_redirects not configured (found: {config.get('all_value')})")
        if not default_config_ok:
            issues.append(f"default.accept_redirects not configured (found: {config.get('default_value')})")
        if not all_runtime_ok:
            issues.append(f"all.accept_redirects enabled at runtime (value: {runtime.get('all_runtime')})")
        if not default_runtime_ok:
            issues.append(f"default.accept_redirects enabled at runtime (value: {runtime.get('default_runtime')})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"ICMP redirect issues: {'; '.join(issues)}",
            remediation=(
                "Disable ICMP redirect acceptance:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.conf.all.accept_redirects = 0\n"
                "   net.ipv4.conf.default.accept_redirects = 0\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
