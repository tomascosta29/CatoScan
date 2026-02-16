"""
CIS Audit Check: Kernel Exec-Shield (if applicable)

Checks if kernel exec-shield protection is enabled.
Exec-shield is a security feature that helps protect against
stack and buffer overflow attacks by marking memory regions
as non-executable.

Note: Modern Linux kernels use NX (No-eXecute) bit support instead
of exec-shield, but this check verifies exec-shield settings if present.
"""

import glob
import os
import re
import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class KernelExecShieldCheck(BaseCheck):
    """Check kernel exec-shield configuration."""

    id = "kernel_exec_shield"
    name = "Kernel Exec-Shield"
    description = (
        "Verifies that kernel exec-shield protection is enabled to help "
        "protect against stack and buffer overflow attacks"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SYSCTL_PATHS = [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/*.conf",
        "/usr/lib/sysctl.d/*.conf",
        "/run/sysctl.d/*.conf",
    ]

    def _check_sysctl_config(self) -> dict:
        """Check sysctl configuration for exec-shield settings.

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

                                if "kernel.exec-shield" in line:
                                    match = re.search(
                                        r'kernel\.exec-shield\s*=\s*(\d+)',
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
                ["sysctl", "-n", "kernel.exec-shield"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                return int(proc.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
        return None

    def _check_nx_support(self) -> dict:
        """Check for NX (No-eXecute) bit support in CPU.

        Returns:
            Dictionary with NX support findings
        """
        result = {
            "nx_supported": False,
            "nx_active": False,
        }

        # Check CPU flags for NX support
        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()
                if "nx" in cpuinfo.lower():
                    result["nx_supported"] = True
        except (IOError, OSError):
            pass

        # Check if NX is active via kernel message
        try:
            proc = subprocess.run(
                ["dmesg"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                dmesg_output = proc.stdout.lower()
                if "nx" in dmesg_output or "execute disable" in dmesg_output:
                    result["nx_active"] = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the kernel exec-shield check.

        Returns:
            CheckResult with the outcome of the check
        """
        sysctl_config = self._check_sysctl_config()
        runtime_value = self._get_runtime_value()
        nx_support = self._check_nx_support()

        details = {
            "sysctl_config": sysctl_config,
            "runtime_value": runtime_value,
            "nx_support": nx_support,
        }

        # Check if sysctl parameter exists (it may not on modern kernels)
        if runtime_value is None and not sysctl_config["configured"]:
            # Check for NX support instead
            if nx_support["nx_supported"]:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Exec-shield sysctl not available, but NX (No-eXecute) bit is supported by CPU",
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=details,
                )

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Exec-shield sysctl not available on this kernel (modern kernels use NX bit instead)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if exec-shield is enabled (value = 1)
        exec_shield_enabled = (
            runtime_value == 1 or
            sysctl_config.get("value") == 1
        )

        if exec_shield_enabled:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Kernel exec-shield is enabled",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Kernel exec-shield is not enabled (value: {runtime_value or sysctl_config.get('value')})",
            remediation=(
                "Enable kernel exec-shield:\n\n"
                "1. Add to /etc/sysctl.conf or /etc/sysctl.d/99-security.conf:\n"
                "   kernel.exec-shield = 1\n\n"
                "2. Apply the changes:\n"
                "   sudo sysctl -p\n\n"
                "3. Verify the setting:\n"
                "   sysctl kernel.exec-shield\n\n"
                "Note: On modern kernels, exec-shield may not be available. "
                "Instead, ensure your CPU supports NX (No-eXecute) bit and "
                "it is enabled in BIOS/UEFI."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
