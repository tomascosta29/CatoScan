"""
CIS Audit Check: GRUB Bootloader Password (CIS 1.3.1)

Checks if GRUB bootloader password is configured to prevent
unauthorized access to the boot loader during system startup.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class GrubPasswordCheck(BaseCheck):
    """Check if GRUB bootloader password is configured."""

    id = "boot_grub_password"
    name = "GRUB Bootloader Password"
    description = (
        "Verifies that a password is configured for the GRUB bootloader "
        "to prevent unauthorized access to the boot loader during system startup"
    )
    severity = Severity.CRITICAL
    requires_root = True

    # GRUB configuration files and directories to check
    DEFAULT_GRUB_CFG_PATHS = [
        "/boot/grub2/grub.cfg",
        "/boot/grub/grub.cfg",
        "/boot/efi/EFI/fedora/grub.cfg",
    ]
    DEFAULT_GRUB_D_PATH = "/etc/grub.d"
    DEFAULT_CUSTOM_CFG_PATHS = [
        "/etc/grub.d/40_custom",
        "/etc/grub.d/01_users",
    ]

    def _get_grub_cfg_paths(self) -> list[str]:
        """Get platform-aware GRUB config file path candidates."""
        paths = self.platform_context.get_paths("grub_cfg")
        if paths:
            return paths
        return self.DEFAULT_GRUB_CFG_PATHS

    def _get_grub_d_path(self) -> str:
        """Get platform-aware /etc/grub.d path."""
        for path in self.platform_context.get_paths("grub_dirs"):
            if path.endswith("/grub.d"):
                return path
        return self.DEFAULT_GRUB_D_PATH

    def _get_custom_cfg_paths(self) -> list[str]:
        """Get platform-aware custom GRUB config file paths."""
        paths = self.platform_context.get_paths("grub_custom_configs")
        if paths:
            return paths
        return self.DEFAULT_CUSTOM_CFG_PATHS

    def _find_grub_cfg(self) -> str | None:
        """Find the active GRUB configuration file.

        Returns:
            Path to the GRUB config file, or None if not found
        """
        for path in self._get_grub_cfg_paths():
            if os.path.isfile(path):
                return path
        return None

    def _check_password_in_file(self, file_path: str) -> dict:
        """Check for password configuration in a file.

        Args:
            file_path: Path to the file to check

        Returns:
            Dictionary with check results
        """
        result = {
            "file": file_path,
            "exists": False,
            "readable": False,
            "has_password_pbkdf2": False,
            "has_password": False,
            "has_superuser": False,
            "password_lines": [],
            "superuser_lines": [],
        }

        if not os.path.isfile(file_path):
            return result

        result["exists"] = True

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                result["readable"] = True

                # Check for password_pbkdf2 (hashed password - recommended)
                pbkdf2_pattern = re.compile(
                    r'^\s*password_pbkdf2\s+\S+\s+\S+',
                    re.MULTILINE
                )
                pbkdf2_matches = pbkdf2_pattern.findall(content)
                if pbkdf2_matches:
                    result["has_password_pbkdf2"] = True
                    result["password_lines"].extend(pbkdf2_matches)

                # Check for plain password (less secure but still counts)
                password_pattern = re.compile(
                    r'^\s*password\s+\S+\s+\S+',
                    re.MULTILINE
                )
                password_matches = password_pattern.findall(content)
                if password_matches:
                    result["has_password"] = True
                    result["password_lines"].extend(password_matches)

                # Check for superuser configuration
                superuser_pattern = re.compile(
                    r'^\s*set\s+superusers\s*=\s*["\']?\S+["\']?',
                    re.MULTILINE
                )
                superuser_matches = superuser_pattern.findall(content)
                if superuser_matches:
                    result["has_superuser"] = True
                    result["superuser_lines"].extend(superuser_matches)

        except (PermissionError, OSError):
            result["readable"] = False

        return result

    def _check_grub_d_directory(self) -> dict:
        """Check all files in /etc/grub.d for password configuration.

        Returns:
            Dictionary with check results
        """
        grub_d_path = self._get_grub_d_path()
        result = {
            "directory": grub_d_path,
            "exists": False,
            "files_checked": [],
            "files_with_password": [],
            "has_password_pbkdf2": False,
            "has_password": False,
            "has_superuser": False,
        }

        if not os.path.isdir(grub_d_path):
            return result

        result["exists"] = True

        try:
            for filename in sorted(os.listdir(grub_d_path)):
                # Skip backup files and README
                if filename.endswith("~") or filename == "README":
                    continue

                file_path = os.path.join(grub_d_path, filename)
                if not os.path.isfile(file_path):
                    continue

                file_result = self._check_password_in_file(file_path)
                result["files_checked"].append(filename)

                if file_result["has_password_pbkdf2"] or file_result["has_password"]:
                    result["files_with_password"].append(filename)
                    if file_result["has_password_pbkdf2"]:
                        result["has_password_pbkdf2"] = True
                    if file_result["has_password"]:
                        result["has_password"] = True

                if file_result["has_superuser"]:
                    result["has_superuser"] = True

        except (PermissionError, OSError):
            pass

        return result

    def _check_custom_files(self) -> list[dict]:
        """Check custom GRUB configuration files.

        Returns:
            List of check results for each file
        """
        results = []
        for file_path in self._get_custom_cfg_paths():
            result = self._check_password_in_file(file_path)
            results.append(result)
        return results

    def run(self) -> CheckResult:
        """Execute the GRUB password check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Find the main GRUB configuration file
        grub_cfg = self._find_grub_cfg()
        grub_cfg_result = None

        if grub_cfg:
            grub_cfg_result = self._check_password_in_file(grub_cfg)

        # Check /etc/grub.d directory
        grub_d_result = self._check_grub_d_directory()

        # Check custom configuration files
        custom_results = self._check_custom_files()

        # Determine if password is configured
        has_password = False
        has_pbkdf2 = False
        has_superuser = False

        # Check main config
        if grub_cfg_result:
            if grub_cfg_result["has_password_pbkdf2"]:
                has_password = True
                has_pbkdf2 = True
            if grub_cfg_result["has_password"]:
                has_password = True
            if grub_cfg_result["has_superuser"]:
                has_superuser = True

        # Check grub.d
        if grub_d_result["has_password_pbkdf2"]:
            has_password = True
            has_pbkdf2 = True
        if grub_d_result["has_password"]:
            has_password = True
        if grub_d_result["has_superuser"]:
            has_superuser = True

        # Check custom files
        for result in custom_results:
            if result["has_password_pbkdf2"]:
                has_password = True
                has_pbkdf2 = True
            if result["has_password"]:
                has_password = True
            if result["has_superuser"]:
                has_superuser = True

        details = {
            "grub_cfg_path": grub_cfg,
            "grub_cfg_result": grub_cfg_result,
            "grub_d_result": grub_d_result,
            "custom_results": custom_results,
            "has_password": has_password,
            "has_pbkdf2": has_pbkdf2,
            "has_superuser": has_superuser,
        }

        if has_password:
            password_type = "PBKDF2 hashed" if has_pbkdf2 else "plain text"
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"GRUB bootloader password is configured ({password_type} password)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not grub_cfg:
            issues.append("GRUB configuration file not found")
        elif not grub_cfg_result or not grub_cfg_result["readable"]:
            issues.append("Cannot read GRUB configuration file")

        if not grub_d_result["exists"]:
            issues.append("GRUB configuration directory not found")

        if not has_superuser:
            issues.append("No superuser configured for GRUB")

        message = "GRUB bootloader password is not configured"
        if issues:
            message += f" ({'; '.join(issues)})"

        custom_cfg_paths = self._get_custom_cfg_paths()
        custom_cfg_target = custom_cfg_paths[0] if custom_cfg_paths else "/etc/grub.d/40_custom"

        mkconfig_targets: list[str] = []
        if grub_cfg:
            mkconfig_targets.append(grub_cfg)
        for candidate in self._get_grub_cfg_paths():
            if candidate not in mkconfig_targets:
                mkconfig_targets.append(candidate)

        mkconfig_commands = [
            self._platform_grub_mkconfig_command(target)
            for target in mkconfig_targets
        ]
        hash_cmd = self._platform_grub_password_hash_command()

        remediation_lines = [
            "GRUB bootloader password is not configured. To secure the bootloader:",
            "",
            "1. Create a GRUB password hash:",
            f"   {hash_cmd}",
            "   (Enter your desired password when prompted)",
            "",
            f"2. Create/edit {custom_cfg_target}:",
            f"   sudo nano {custom_cfg_target}",
            "",
            "3. Add the following lines (replace HASH with your generated hash):",
            "   set superusers=\"root\"",
            "   password_pbkdf2 root HASH",
            "",
            "4. Regenerate GRUB configuration:",
        ]

        for cmd in mkconfig_commands:
            remediation_lines.append(f"   {cmd}")

        remediation_lines.extend([
            "",
            "5. Reboot and verify:",
            "   sudo reboot",
            "",
            "Note: Without a GRUB password, anyone with physical access can:",
            "- Boot into single-user mode without authentication",
            "- Modify kernel parameters to bypass security",
            "- Access the system without entering system passwords",
            "",
            "CIS Benchmark: 1.3.1 - Ensure bootloader password is set",
        ])

        remediation = "\n".join(remediation_lines)

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=message,
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
