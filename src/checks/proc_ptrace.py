"""
CIS Audit Check: Ptrace Scope Restricted (1.4.4)

Ensures the ptrace scope is restricted via sysctl to prevent processes
from examining the memory of other processes, which can expose sensitive data.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class PtraceCheck(BaseCheck):
    """Check that ptrace scope is restricted."""

    id = "proc_ptrace"
    name = "Ptrace Scope Restricted"
    description = (
        "Ensures the ptrace scope is restricted via sysctl to prevent "
        "processes from examining the memory of other processes"
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
    YAMA_PTRACE = "kernel.yama.ptrace_scope"

    def _read_config_files(self) -> dict:
        """Read sysctl configuration files for ptrace_scope settings.

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

                                if self.YAMA_PTRACE in line:
                                    match = re.search(
                                        rf'{re.escape(self.YAMA_PTRACE)}\s*=\s*(\d+)',
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
                ["sysctl", "-n", self.YAMA_PTRACE],
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
        """Execute the ptrace scope check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_config_files()
        runtime = self._get_runtime_value()

        details = {
            "config": config,
            "runtime_value": runtime,
        }

        # Ptrace scope should be 1 (restricted) or higher
        # 0 = classic ptrace permissions (no restrictions)
        # 1 = restricted ptrace (requires PTRACE_MODE_ATTACH or CAP_SYS_PTRACE)
        # 2 = admin-only attach (requires CAP_SYS_PTRACE)
        # 3 = no attach (no process can call ptrace)
        config_ok = config.get("value") is not None and config.get("value") >= 1
        runtime_ok = runtime is not None and runtime >= 1

        all_ok = config_ok and runtime_ok

        if all_ok:
            scope_desc = {
                1: "restricted (1) - requires PTRACE_MODE_ATTACH or CAP_SYS_PTRACE",
                2: "admin-only (2) - requires CAP_SYS_PTRACE",
                3: "no attach (3) - ptrace completely disabled",
            }
            runtime_desc = scope_desc.get(runtime, f"value {runtime}")
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Ptrace scope is restricted ({runtime_desc})",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not config_ok:
            if not config.get("configured"):
                issues.append("kernel.yama.ptrace_scope not configured")
            else:
                issues.append(
                    f"kernel.yama.ptrace_scope set to {config.get('value')}, expected >= 1"
                )
        if not runtime_ok:
            if runtime is None:
                issues.append("kernel.yama.ptrace_scope not available at runtime")
            else:
                issues.append(
                    f"kernel.yama.ptrace_scope is {runtime} at runtime, expected >= 1"
                )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Ptrace scope issues: {'; '.join(issues)}",
            remediation=(
                "Restrict ptrace scope:\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   kernel.yama.ptrace_scope = 1\n"
                "2. Apply changes: sudo sysctl -p\n"
                "3. Verify: sysctl kernel.yama.ptrace_scope\n"
                "\n"
                "Ptrace scope values:\n"
                "  0 = classic ptrace permissions (no restrictions)\n"
                "  1 = restricted ptrace (recommended)\n"
                "  2 = admin-only attach\n"
                "  3 = no attach (completely disabled)"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
