"""
CIS Audit Check: Suspicious Packets Logged (3.2.4)

Ensures suspicious packets (martians) are logged to detect potential attacks.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class LogMartiansCheck(BaseCheck):
    """Check that suspicious packets are logged."""

    id = "net_log_martians"
    name = "Suspicious Packets Logged"
    description = (
        "Ensures the system logs suspicious packets (martians) "
        "to help detect potential network attacks"
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
    ALL_LOG_MARTIANS = "net.ipv4.conf.all.log_martians"
    DEFAULT_LOG_MARTIANS = "net.ipv4.conf.default.log_martians"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for log_martians settings.

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

                                # Check all.log_martians
                                if self.ALL_LOG_MARTIANS in line:
                                    match = re.search(rf'{re.escape(self.ALL_LOG_MARTIANS)}\s*=\s*(\d+)', line)
                                    if match:
                                        result["all_configured"] = True
                                        result["all_value"] = int(match.group(1))
                                        result["all_config_file"] = f"{path}:{line_num}"

                                # Check default.log_martians
                                if self.DEFAULT_LOG_MARTIANS in line:
                                    match = re.search(rf'{re.escape(self.DEFAULT_LOG_MARTIANS)}\s*=\s*(\d+)', line)
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

        # Check all.log_martians
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.ALL_LOG_MARTIANS],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                result["all_runtime"] = int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

        # Check default.log_martians
        try:
            proc = subprocess.run(
                ["sysctl", "-n", self.DEFAULT_LOG_MARTIANS],
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
        """Execute the log martians check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_values()

        details = {
            "config": config,
            "runtime": runtime,
        }

        all_config_ok = config.get("all_value") == 1
        default_config_ok = config.get("default_value") == 1
        all_runtime_ok = runtime.get("all_runtime") == 1
        default_runtime_ok = runtime.get("default_runtime") == 1

        # Determine overall status
        all_ok = all_config_ok and default_config_ok and all_runtime_ok and default_runtime_ok

        if all_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Suspicious packets (martians) are being logged",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not all_config_ok:
            issues.append(f"all.log_martians not configured to 1 (found: {config.get('all_value')})")
        if not default_config_ok:
            issues.append(f"default.log_martians not configured to 1 (found: {config.get('default_value')})")
        if not all_runtime_ok:
            issues.append(f"all.log_martians not enabled at runtime (value: {runtime.get('all_runtime')})")
        if not default_runtime_ok:
            issues.append(f"default.log_martians not enabled at runtime (value: {runtime.get('default_runtime')})")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Log martians issues: {'; '.join(issues)}",
            remediation=(
                "Enable logging of suspicious packets:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   net.ipv4.conf.all.log_martians = 1\n"
                "   net.ipv4.conf.default.log_martians = 1\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians\n"
                "4. Check logs: sudo dmesg | grep martian"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
