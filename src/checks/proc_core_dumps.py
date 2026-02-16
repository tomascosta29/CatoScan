"""
CIS Audit Check: Core Dumps Restricted (1.4.1)

Ensures core dumps are restricted via limits.conf and sysctl to prevent
sensitive information exposure.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class CoreDumpsCheck(BaseCheck):
    """Check that core dumps are restricted."""

    id = "proc_core_dumps"
    name = "Core Dumps Restricted"
    description = (
        "Ensures core dumps are restricted via limits.conf and sysctl "
        "to prevent exposure of sensitive information"
    )
    severity = Severity.HIGH
    requires_root = True

    # Configuration files
    LIMITS_CONF = "/etc/security/limits.conf"
    LIMITS_D_DIR = "/etc/security/limits.d"
    SYSCTL_PATHS = [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/*.conf",
        "/usr/lib/sysctl.d/*.conf",
        "/run/sysctl.d/*.conf",
    ]

    def _check_limits_conf(self) -> dict:
        """Check limits.conf for core dump restrictions.

        Returns:
            Dictionary with limits configuration findings
        """
        result = {
            "configured": False,
            "value": None,
            "config_file": None,
            "config_files_checked": [],
        }

        # Check main limits.conf
        files_to_check = [self.LIMITS_CONF]
        
        # Check limits.d directory
        if os.path.isdir(self.LIMITS_D_DIR):
            for f in os.listdir(self.LIMITS_D_DIR):
                if f.endswith(".conf"):
                    files_to_check.append(os.path.join(self.LIMITS_D_DIR, f))

        for path in files_to_check:
            if os.path.isfile(path):
                result["config_files_checked"].append(path)
                try:
                    with open(path, "r") as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue

                            # Check for core dump limit (hard or soft)
                            # Pattern: * hard core 0 or * soft core 0
                            match = re.search(
                                r'^\*\s+(hard|soft|-)\s+core\s+(\d+|\*)',
                                line
                            )
                            if match:
                                limit_type = match.group(1)
                                value = match.group(2)
                                result["configured"] = True
                                result["value"] = value
                                result["limit_type"] = limit_type
                                result["config_file"] = f"{path}:{line_num}"
                                # If hard limit is 0, core dumps are disabled
                                if limit_type == "hard" and value == "0":
                                    result["core_disabled"] = True
                                    return result

                except (IOError, OSError):
                    pass

        return result

    def _check_sysctl_fs_suid_dumpable(self) -> dict:
        """Check sysctl fs.suid_dumpable setting.

        Returns:
            Dictionary with sysctl configuration findings
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

                                if "fs.suid_dumpable" in line:
                                    match = re.search(
                                        r'fs\.suid_dumpable\s*=\s*(\d+)',
                                        line
                                    )
                                    if match:
                                        result["configured"] = True
                                        result["value"] = int(match.group(1))
                                        result["config_file"] = f"{path}:{line_num}"

                    except (IOError, OSError):
                        pass

        return result

    def _get_runtime_value(self, param: str) -> int | None:
        """Get current runtime value from sysctl.

        Args:
            param: Sysctl parameter name

        Returns:
            Runtime value or None if unavailable
        """
        try:
            proc = subprocess.run(
                ["sysctl", "-n", param],
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
        """Execute the core dumps restriction check.

        Returns:
            CheckResult with the outcome of the check
        """
        limits_config = self._check_limits_conf()
        sysctl_config = self._check_sysctl_fs_suid_dumpable()
        runtime_suid_dumpable = self._get_runtime_value("fs.suid_dumpable")

        details = {
            "limits_config": limits_config,
            "sysctl_config": sysctl_config,
            "runtime_fs_suid_dumpable": runtime_suid_dumpable,
        }

        # Check if hard core limit is set to 0
        limits_ok = (
            limits_config.get("configured") and
            limits_config.get("limit_type") == "hard" and
            limits_config.get("value") == "0"
        )

        # Check if fs.suid_dumpable is set to 0
        sysctl_ok = sysctl_config.get("value") == 0
        runtime_ok = runtime_suid_dumpable == 0

        all_ok = limits_ok and sysctl_ok and runtime_ok

        if all_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Core dumps are properly restricted",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not limits_ok:
            if not limits_config.get("configured"):
                issues.append("core limit not configured in limits.conf")
            else:
                issues.append(
                    f"core limit set to '{limits_config.get('value')}' "
                    f"(type: {limits_config.get('limit_type')}), expected hard 0"
                )
        if not sysctl_ok:
            issues.append(
                f"fs.suid_dumpable not configured to 0 (found: {sysctl_config.get('value')})"
            )
        if not runtime_ok:
            issues.append(
                f"fs.suid_dumpable not 0 at runtime (value: {runtime_suid_dumpable})"
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Core dumps restriction issues: {'; '.join(issues)}",
            remediation=(
                "Restrict core dumps:\n"
                "1. Add to /etc/security/limits.conf:\n"
                "   * hard core 0\n"
                "2. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   fs.suid_dumpable = 0\n"
                "3. Apply sysctl changes: sudo sysctl -p\n"
                "4. Verify: sysctl fs.suid_dumpable"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
