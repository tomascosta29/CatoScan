"""
CIS Audit Check: SELinux Enforcing Mode

Checks that SELinux is in enforcing mode.
CIS 1.5.1.4
"""

import os
import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxEnforcingCheck(BaseCheck):
    """Check that SELinux is in enforcing mode."""

    id = "selinux_enforcing"
    name = "SELinux Enforcing Mode"
    description = (
        "Verifies that SELinux is currently in enforcing mode and "
        "configured to enforce on boot"
    )
    severity = Severity.HIGH
    requires_root = True

    SELINUX_CONFIG = "/etc/selinux/config"

    def _get_runtime_mode(self) -> tuple[str | None, dict]:
        """Get current SELinux runtime mode.

        Returns:
            Tuple of (mode, details)
        """
        details = {"methods_tried": []}

        # Try getenforce command first
        try:
            details["methods_tried"].append("getenforce")
            result = subprocess.run(
                ["getenforce"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                mode = result.stdout.strip().lower()
                details["getenforce_output"] = mode
                return mode, details
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["getenforce_error"] = str(e)

        # Fallback to /sys/fs/selinux/enforce
        try:
            details["methods_tried"].append("/sys/fs/selinux/enforce")
            enforce_path = "/sys/fs/selinux/enforce"
            if os.path.exists(enforce_path):
                with open(enforce_path, "r") as f:
                    value = f.read().strip()
                    details["enforce_file_value"] = value
                    if value == "1":
                        return "enforcing", details
                    elif value == "0":
                        return "permissive", details
        except (IOError, OSError) as e:
            details["enforce_file_error"] = str(e)

        return None, details

    def _get_config_mode(self) -> tuple[str | None, dict]:
        """Get SELinux mode from configuration file.

        Returns:
            Tuple of (mode, details)
        """
        details = {"file_exists": False}

        if not os.path.exists(self.SELINUX_CONFIG):
            return None, details

        details["file_exists"] = True

        try:
            with open(self.SELINUX_CONFIG, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue

                    if line.startswith("SELINUX="):
                        mode = line.split("=", 1)[1].strip().strip('"\'').lower()
                        details["config_line"] = line
                        details["mode_found"] = mode
                        return mode, details

        except (IOError, OSError) as e:
            details["error"] = str(e)

        return None, details

    def run(self) -> CheckResult:
        """Execute the SELinux enforcing mode check.

        Returns:
            CheckResult with the outcome of the check
        """
        runtime_mode, runtime_details = self._get_runtime_mode()
        config_mode, config_details = self._get_config_mode()

        details = {
            "runtime": runtime_details,
            "config": config_details,
            "runtime_mode": runtime_mode,
            "config_mode": config_mode,
        }

        # Check if SELinux is available at all
        if runtime_mode is None and not config_details.get("file_exists"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="SELinux does not appear to be installed or accessible",
                remediation="Install SELinux packages and configure properly",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []

        # Check runtime mode
        if runtime_mode is None:
            issues.append("Unable to determine current SELinux runtime mode")
        elif runtime_mode != "enforcing":
            issues.append(f"SELinux is in {runtime_mode} mode (should be enforcing)")

        # Check config mode
        if config_mode is None:
            issues.append("SELINUX mode not configured in /etc/selinux/config")
        elif config_mode != "enforcing":
            issues.append(f"SELINUX={config_mode} in config (should be enforcing)")

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"SELinux is not in enforcing mode: {'; '.join(issues)}",
                remediation=(
                    "Set SELinux to enforcing mode:\n"
                    "1. Edit /etc/selinux/config and set:\n"
                    "   SELINUX=enforcing\n"
                    "2. Set runtime mode to enforcing:\n"
                    "   setenforce 1\n"
                    "3. Reboot to ensure changes persist\n\n"
                    "Or to set without reboot:\n"
                    "   setenforce 1"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="SELinux is in enforcing mode (runtime and configured)",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
