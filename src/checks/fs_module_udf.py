"""
CIS Audit Check: udf Filesystem Module Disabled

Checks if the udf filesystem module is disabled (CIS 1.1.1.7).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class UdfModuleCheck(BaseCheck):
    """Check if udf filesystem module is disabled."""

    id = "fs_module_udf"
    name = "udf Filesystem Module Disabled"
    description = (
        "Verifies that the udf filesystem module is disabled "
        "to reduce attack surface"
    )
    severity = Severity.LOW
    requires_root = True

    # Kernel module name
    MODULE_NAME = "udf"

    # Modprobe config paths
    MODPROBE_PATHS = [
        "/etc/modprobe.d",
        "/etc/modprobe.conf",
    ]

    def _check_module_loaded(self) -> bool:
        """Check if the module is currently loaded.

        Returns:
            True if module is loaded, False otherwise
        """
        try:
            result = subprocess.run(
                ["lsmod"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith(self.MODULE_NAME + " "):
                        return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return False

    def _check_modprobe_config(self) -> tuple[bool, bool, list[dict]]:
        """Check modprobe configuration for module blacklisting.

        Returns:
            Tuple of (has_install_true, has_blacklist, configs)
        """
        has_install_true = False
        has_blacklist = False
        configs = []

        # Check /etc/modprobe.d directory
        modprobe_d = Path("/etc/modprobe.d")
        if modprobe_d.exists() and modprobe_d.is_dir():
            try:
                for config_file in modprobe_d.iterdir():
                    if config_file.is_file() and config_file.suffix == ".conf":
                        try:
                            with open(config_file, "r") as f:
                                for line in f:
                                    line = line.strip()
                                    if not line or line.startswith("#"):
                                        continue
                                    if self.MODULE_NAME in line:
                                        configs.append({
                                            "file": str(config_file),
                                            "line": line,
                                        })
                                        # Check for install /bin/true pattern
                                        if (f"install {self.MODULE_NAME}" in line or
                                            line.startswith(f"install {self.MODULE_NAME}")):
                                            if "/bin/true" in line or "/bin/false" in line:
                                                has_install_true = True
                                        # Check for blacklist pattern
                                        if (f"blacklist {self.MODULE_NAME}" in line or
                                            line.startswith(f"blacklist {self.MODULE_NAME}")):
                                            has_blacklist = True
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass

        # Check /etc/modprobe.conf
        modprobe_conf = Path("/etc/modprobe.conf")
        if modprobe_conf.exists():
            try:
                with open(modprobe_conf, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if self.MODULE_NAME in line:
                            configs.append({
                                "file": str(modprobe_conf),
                                "line": line,
                            })
                            if (f"install {self.MODULE_NAME}" in line or
                                line.startswith(f"install {self.MODULE_NAME}")):
                                if "/bin/true" in line or "/bin/false" in line:
                                    has_install_true = True
                            if (f"blacklist {self.MODULE_NAME}" in line or
                                line.startswith(f"blacklist {self.MODULE_NAME}")):
                                has_blacklist = True
            except (PermissionError, OSError):
                pass

        return has_install_true, has_blacklist, configs

    def run(self) -> CheckResult:
        """Execute the udf module disabled check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if module is loaded
        module_loaded = self._check_module_loaded()

        # Check modprobe configuration
        has_install_true, has_blacklist, modprobe_configs = self._check_modprobe_config()

        details = {
            "module_loaded": module_loaded,
            "has_install_true": has_install_true,
            "has_blacklist": has_blacklist,
            "modprobe_configs": modprobe_configs,
        }

        # Determine result - pass if module not loaded AND properly configured
        if not module_loaded and has_install_true and has_blacklist:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.MODULE_NAME} module is disabled (not loaded, blacklisted in modprobe)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if module_loaded:
            issues.append(f"{self.MODULE_NAME} kernel module is loaded")
        if not has_install_true:
            issues.append(f"{self.MODULE_NAME} does not have 'install /bin/true' in modprobe config")
        if not has_blacklist:
            issues.append(f"{self.MODULE_NAME} is not blacklisted in modprobe config")

        # Build remediation
        remediation_parts = [
            f"Disable {self.MODULE_NAME} filesystem module:",
            "",
            f"1. Create or edit /etc/modprobe.d/{self.MODULE_NAME}.conf:",
            f"   echo 'install {self.MODULE_NAME} /bin/true' | sudo tee /etc/modprobe.d/{self.MODULE_NAME}.conf",
            f"   echo 'blacklist {self.MODULE_NAME}' | sudo tee -a /etc/modprobe.d/{self.MODULE_NAME}.conf",
            "",
            "2. Unload the module if currently loaded:",
            f"   sudo modprobe -r {self.MODULE_NAME}",
            "",
            "3. Update initramfs to apply changes at boot:",
            "   sudo dracut -f",
            "",
            "4. Verify the module is disabled:",
            f"   lsmod | grep {self.MODULE_NAME}",
            f"   cat /etc/modprobe.d/{self.MODULE_NAME}.conf",
        ]

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
