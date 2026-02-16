"""
CIS Audit Check: SELinux Not Disabled in Bootloader

Checks that SELinux is not disabled via kernel parameters in GRUB.
CIS 1.5.1.2
"""

import os
import re
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxBootloaderCheck(BaseCheck):
    """Check that SELinux is not disabled in bootloader configuration."""

    id = "selinux_bootloader"
    name = "SELinux Not Disabled in Bootloader"
    description = (
        "Verifies that SELinux is not disabled via kernel parameters "
        "in GRUB bootloader configuration"
    )
    severity = Severity.HIGH
    requires_root = True

    DEFAULT_GRUB_CONFIG_FILES = [
        "/etc/default/grub",
        "/boot/grub2/grub.cfg",
        "/boot/grub/grub.cfg",
    ]

    def _get_grub_config_files(self) -> list[str]:
        """Get platform-aware GRUB config files to inspect."""
        paths: list[str] = []
        paths.extend(self.platform_context.get_paths("grub_default_config"))
        paths.extend(self.platform_context.get_paths("grub_cfg"))

        if not paths:
            return self.DEFAULT_GRUB_CONFIG_FILES

        deduped: list[str] = []
        for path in paths:
            if path not in deduped:
                deduped.append(path)
        return deduped

    def _preferred_grub_output_path(self) -> str:
        """Get best GRUB config output path for regeneration command."""
        cfg_paths = self.platform_context.get_paths("grub_cfg")
        for path in cfg_paths:
            if os.path.exists(path):
                return path
        if cfg_paths:
            return cfg_paths[0]
        return "/boot/grub2/grub.cfg"

    def _check_grub_config(self) -> tuple[bool, list[str], dict]:
        """Check GRUB configuration for SELinux disabling parameters.

        Returns:
            Tuple of (has_disable_param, found_params, details)
        """
        details = {
            "files_checked": [],
            "disable_params_found": [],
            "config_lines": [],
        }
        has_disable = False
        found_params = []

        # Patterns that disable SELinux
        disable_patterns = [
            r"selinux=0",
            r"enforcing=0",
            r"selinux=disabled",
        ]

        for grub_file in self._get_grub_config_files():
            if not os.path.exists(grub_file):
                continue

            details["files_checked"].append(grub_file)

            try:
                with open(grub_file, "r") as f:
                    content = f.read()

                for line_num, line in enumerate(content.split("\n"), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    for pattern in disable_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            has_disable = True
                            found_params.append(pattern.replace(r"\b", ""))
                            details["disable_params_found"].append({
                                "file": grub_file,
                                "line": line_num,
                                "content": line,
                                "pattern": pattern,
                            })

            except (IOError, OSError) as e:
                details.setdefault("errors", []).append(f"{grub_file}: {str(e)}")

        return has_disable, found_params, details

    def run(self) -> CheckResult:
        """Execute the SELinux bootloader check.

        Returns:
            CheckResult with the outcome of the check
        """
        has_disable, found_params, details = self._check_grub_config()

        if has_disable:
            grub_default_cfg = self.platform_context.get_paths("grub_default_config")
            grub_default_path = grub_default_cfg[0] if grub_default_cfg else "/etc/default/grub"
            mkconfig_cmd = self._platform_grub_mkconfig_command(self._preferred_grub_output_path())

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"SELinux is disabled in bootloader configuration: {', '.join(set(found_params))}",
                remediation=(
                    "Remove SELinux disabling parameters from GRUB configuration:\n"
                    f"1. Edit {grub_default_path}\n"
                    "2. Remove 'selinux=0', 'enforcing=0', or 'selinux=disabled' from GRUB_CMDLINE_LINUX\n"
                    "3. Regenerate GRUB configuration:\n"
                    f"   {mkconfig_cmd}\n"
                    "4. Reboot the system"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="SELinux is not disabled in bootloader configuration",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
