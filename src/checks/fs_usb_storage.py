"""
CIS Audit Check: USB Storage Disabled

Checks if USB storage is disabled (CIS 1.1.22).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class USBStorageDisabledCheck(BaseCheck):
    """Check if USB storage is disabled."""

    id = "fs_usb_storage"
    name = "USB Storage Disabled"
    description = (
        "Verifies that USB storage is disabled to prevent "
        "unauthorized data exfiltration or introduction of malware"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Kernel module name for USB storage
    USB_STORAGE_MODULE = "usb-storage"

    # Modprobe config files to check
    MODPROBE_PATHS = [
        "/etc/modprobe.d",
        "/etc/modprobe.conf",
        "/usr/lib/modprobe.d",
    ]

    def _check_module_loaded(self) -> bool:
        """Check if the USB storage module is currently loaded.

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
                    if line.startswith(self.USB_STORAGE_MODULE):
                        return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return False

    def _check_modprobe_config(self) -> list[dict]:
        """Check modprobe configuration for USB storage blacklisting.

        Returns:
            List of found blacklist configurations
        """
        configs = []

        # Check /etc/modprobe.d directory
        modprobe_d = Path("/etc/modprobe.d")
        if modprobe_d.exists() and modprobe_d.is_dir():
            try:
                for config_file in modprobe_d.iterdir():
                    if config_file.is_file():
                        try:
                            with open(config_file, "r") as f:
                                content = f.read()
                                # Check for blacklist or install lines for usb-storage
                                for line in content.splitlines():
                                    line = line.strip()
                                    if line.startswith("#"):
                                        continue
                                    if self.USB_STORAGE_MODULE in line:
                                        if ("blacklist" in line or
                                            "install" in line or
                                            "options" in line):
                                            configs.append({
                                                "file": str(config_file),
                                                "line": line,
                                            })
                        except (PermissionError, OSError):
                            pass
            except (PermissionError, OSError):
                pass

        # Check /etc/modprobe.conf
        modprobe_conf = Path("/etc/modprobe.conf")
        if modprobe_conf.exists():
            try:
                with open(modprobe_conf, "r") as f:
                    content = f.read()
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        if self.USB_STORAGE_MODULE in line:
                            if ("blacklist" in line or
                                "install" in line or
                                "options" in line):
                                configs.append({
                                    "file": str(modprobe_conf),
                                    "line": line,
                                })
            except (PermissionError, OSError):
                pass

        return configs

    def _is_usb_storage_disabled(self, configs: list[dict]) -> bool:
        """Determine if USB storage is properly disabled based on config.

        Args:
            configs: List of modprobe configurations

        Returns:
            True if USB storage is disabled, False otherwise
        """
        for config in configs:
            line = config.get("line", "")
            # Check for proper disable patterns
            if "install" in line and "/bin/true" in line:
                return True
            if "install" in line and "/bin/false" in line:
                return True
            if "options" in line and "disable" in line:
                return True
        return False

    def run(self) -> CheckResult:
        """Execute the USB storage disabled check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if module is loaded
        module_loaded = self._check_module_loaded()

        # Check modprobe configuration
        modprobe_configs = self._check_modprobe_config()
        properly_disabled = self._is_usb_storage_disabled(modprobe_configs)

        details = {
            "module_loaded": module_loaded,
            "modprobe_configs": modprobe_configs,
            "properly_disabled": properly_disabled,
        }

        # Determine result
        if not module_loaded and properly_disabled:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="USB storage is disabled (module not loaded, blacklisted in modprobe)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if module_loaded:
            issues.append("usb-storage kernel module is loaded")
        if not properly_disabled:
            issues.append("usb-storage is not blacklisted in modprobe configuration")

        # Build remediation
        remediation_parts = [
            "Disable USB storage:",
            "",
            "1. Create or edit /etc/modprobe.d/usb-storage.conf:",
            "   echo 'install usb-storage /bin/true' | sudo tee /etc/modprobe.d/usb-storage.conf",
            "",
            "2. Unload the module if currently loaded:",
            "   sudo modprobe -r usb-storage",
            "",
            "3. Update initramfs to apply changes at boot:",
            "   sudo dracut -f",
            "",
            "4. Verify USB storage is disabled:",
            "   lsmod | grep usb-storage",
            "   cat /etc/modprobe.d/usb-storage.conf",
            "",
            "Note: If USB storage is needed for legitimate purposes, consider:",
            "      - Using USB device authorization instead of full disable",
            "      - Implementing USBGuard for granular control",
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
