"""
CIS Audit Check: ASLR Enabled (1.4.2)

Ensures Address Space Layout Randomization (ASLR) is enabled via sysctl
to make exploitation of memory corruption vulnerabilities more difficult.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class ASLRCheck(BaseCheck):
    """Check that ASLR is enabled."""

    id = "proc_aslr"
    name = "ASLR Enabled"
    description = (
        "Ensures Address Space Layout Randomization (ASLR) is enabled "
        "via sysctl to make exploitation of memory corruption vulnerabilities more difficult"
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
    KERNEL_RANDOMIZE = "kernel.randomize_va_space"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for ASLR settings.

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

                                if self.KERNEL_RANDOMIZE in line:
                                    match = re.search(
                                        rf'{re.escape(self.KERNEL_RANDOMIZE)}\s*=\s*(\d+)',
                                        line
                                    )
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
                ["sysctl", "-n", self.KERNEL_RANDOMIZE],
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
        """Execute the ASLR check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_value()

        details = {
            "config": config,
            "runtime_value": runtime,
        }

        # ASLR is fully enabled when value is 2
        # 0 = disabled, 1 = conservative randomization, 2 = full randomization
        config_ok = config.get("value") == 2
        runtime_ok = runtime == 2

        all_ok = config_ok and runtime_ok

        if all_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="ASLR is fully enabled (kernel.randomize_va_space = 2)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not config_ok:
            if not config.get("configured"):
                issues.append("kernel.randomize_va_space not configured")
            else:
                issues.append(
                    f"kernel.randomize_va_space set to {config.get('value')}, expected 2"
                )
        if not runtime_ok:
            issues.append(
                f"kernel.randomize_va_space is {runtime} at runtime, expected 2"
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"ASLR issues: {'; '.join(issues)}",
            remediation=(
                "Enable full ASLR:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   kernel.randomize_va_space = 2\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl kernel.randomize_va_space\n"
                "\n"
                "Note: Value 2 provides full randomization. "
                "Value 1 provides conservative randomization."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
