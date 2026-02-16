"""
CIS Audit Check: GRUB Bootloader Permissions (CIS 1.3.2)

Checks that GRUB bootloader configuration files have appropriate
permissions to prevent unauthorized modification or reading.
"""

import os
import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class GrubPermissionsCheck(BaseCheck):
    """Check GRUB bootloader configuration file permissions."""

    id = "boot_grub_permissions"
    name = "GRUB Bootloader Permissions"
    description = (
        "Verifies that GRUB bootloader configuration files are owned by root "
        "and have restrictive permissions (600 or more restrictive)"
    )
    severity = Severity.CRITICAL
    requires_root = True

    # GRUB configuration files to check
    GRUB_FILES = [
        "/boot/grub2/grub.cfg",
        "/boot/grub/grub.cfg",
        "/boot/efi/EFI/fedora/grub.cfg",
    ]

    # GRUB directories to check
    GRUB_DIRS = [
        "/boot/grub2",
        "/boot/grub",
        "/boot/efi/EFI/fedora",
        "/etc/grub.d",
    ]

    # Maximum allowed permissions (600 = rw-------)
    MAX_FILE_MODE = 0o600
    MAX_DIR_MODE = 0o700

    def _get_grub_files(self) -> list[str]:
        """Get platform-aware GRUB config file paths."""
        paths = self.platform_context.get_paths("grub_cfg")
        if paths:
            return paths
        return self.GRUB_FILES

    def _get_grub_dirs(self) -> list[str]:
        """Get platform-aware GRUB directory paths."""
        paths = self.platform_context.get_paths("grub_dirs")
        if paths:
            return paths
        return self.GRUB_DIRS

    def _check_file_permissions(self, file_path: str) -> dict:
        """Check permissions of a single file.

        Args:
            file_path: Path to the file to check

        Returns:
            Dictionary with check results
        """
        result = {
            "path": file_path,
            "exists": False,
            "is_file": False,
            "owner_uid": None,
            "owner_name": None,
            "group_gid": None,
            "group_name": None,
            "mode": None,
            "mode_string": None,
            "is_root_owned": False,
            "is_root_group": False,
            "is_group_readable": False,
            "is_group_writable": False,
            "is_group_executable": False,
            "is_other_readable": False,
            "is_other_writable": False,
            "is_other_executable": False,
            "is_too_permissive": False,
            "issues": [],
        }

        path = Path(file_path)
        if not path.exists():
            result["issues"].append("file does not exist")
            return result

        result["exists"] = True

        if not path.is_file():
            result["is_file"] = False
            result["issues"].append("path is not a file")
            return result

        result["is_file"] = True

        try:
            stat_info = path.stat()
            mode = stat_info.st_mode

            result["mode"] = oct(mode & 0o7777)
            result["mode_string"] = stat.filemode(mode)
            result["owner_uid"] = stat_info.st_uid
            result["group_gid"] = stat_info.st_gid

            # Check ownership
            result["is_root_owned"] = (stat_info.st_uid == 0)
            result["is_root_group"] = (stat_info.st_gid == 0)

            # Check group permissions
            result["is_group_readable"] = bool(mode & stat.S_IRGRP)
            result["is_group_writable"] = bool(mode & stat.S_IWGRP)
            result["is_group_executable"] = bool(mode & stat.S_IXGRP)

            # Check other permissions
            result["is_other_readable"] = bool(mode & stat.S_IROTH)
            result["is_other_writable"] = bool(mode & stat.S_IWOTH)
            result["is_other_executable"] = bool(mode & stat.S_IXOTH)

            # Determine if too permissive (more than 600)
            # Mask out owner bits to check group/other permissions
            group_other_mode = mode & 0o077
            if group_other_mode != 0:
                result["is_too_permissive"] = True

            # Collect issues
            if not result["is_root_owned"]:
                try:
                    import pwd
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                except KeyError:
                    owner = str(stat_info.st_uid)
                result["issues"].append(f"not owned by root (owner: {owner})")

            if result["is_group_readable"]:
                result["issues"].append("group-readable")
            if result["is_group_writable"]:
                result["issues"].append("group-writable")
            if result["is_other_readable"]:
                result["issues"].append("world-readable")
            if result["is_other_writable"]:
                result["issues"].append("world-writable")

        except (PermissionError, OSError) as e:
            result["issues"].append(f"cannot stat: {str(e)}")

        return result

    def _check_directory_permissions(self, dir_path: str) -> dict:
        """Check permissions of a directory.

        Args:
            dir_path: Path to the directory to check

        Returns:
            Dictionary with check results
        """
        result = {
            "path": dir_path,
            "exists": False,
            "is_directory": False,
            "owner_uid": None,
            "owner_name": None,
            "group_gid": None,
            "group_name": None,
            "mode": None,
            "mode_string": None,
            "is_root_owned": False,
            "is_root_group": False,
            "is_group_readable": False,
            "is_group_writable": False,
            "is_group_executable": False,
            "is_other_readable": False,
            "is_other_writable": False,
            "is_other_executable": False,
            "is_too_permissive": False,
            "issues": [],
        }

        path = Path(dir_path)
        if not path.exists():
            result["issues"].append("directory does not exist")
            return result

        result["exists"] = True

        if not path.is_dir():
            result["is_directory"] = False
            result["issues"].append("path is not a directory")
            return result

        result["is_directory"] = True

        try:
            stat_info = path.stat()
            mode = stat_info.st_mode

            result["mode"] = oct(mode & 0o7777)
            result["mode_string"] = stat.filemode(mode)
            result["owner_uid"] = stat_info.st_uid
            result["group_gid"] = stat_info.st_gid

            # Check ownership
            result["is_root_owned"] = (stat_info.st_uid == 0)
            result["is_root_group"] = (stat_info.st_gid == 0)

            # Check group permissions
            result["is_group_readable"] = bool(mode & stat.S_IRGRP)
            result["is_group_writable"] = bool(mode & stat.S_IWGRP)
            result["is_group_executable"] = bool(mode & stat.S_IXGRP)

            # Check other permissions
            result["is_other_readable"] = bool(mode & stat.S_IROTH)
            result["is_other_writable"] = bool(mode & stat.S_IWOTH)
            result["is_other_executable"] = bool(mode & stat.S_IXOTH)

            # Determine if too permissive (more than 700)
            # For directories, group/other should have no access
            group_other_mode = mode & 0o077
            if group_other_mode != 0:
                result["is_too_permissive"] = True

            # Collect issues
            if not result["is_root_owned"]:
                try:
                    import pwd
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                except KeyError:
                    owner = str(stat_info.st_uid)
                result["issues"].append(f"not owned by root (owner: {owner})")

            if result["is_group_readable"]:
                result["issues"].append("group-readable")
            if result["is_group_writable"]:
                result["issues"].append("group-writable")
            if result["is_group_executable"]:
                result["issues"].append("group-executable")
            if result["is_other_readable"]:
                result["issues"].append("world-readable")
            if result["is_other_writable"]:
                result["issues"].append("world-writable")
            if result["is_other_executable"]:
                result["issues"].append("world-executable")

        except (PermissionError, OSError) as e:
            result["issues"].append(f"cannot stat: {str(e)}")

        return result

    def _check_grub_d_files(self) -> list[dict]:
        """Check all files in /etc/grub.d directory.

        Returns:
            List of check results for each file
        """
        results = []
        grub_d_path = "/etc/grub.d"

        if not os.path.isdir(grub_d_path):
            return results

        try:
            for filename in sorted(os.listdir(grub_d_path)):
                # Skip backup files and README
                if filename.endswith("~") or filename == "README":
                    continue

                file_path = os.path.join(grub_d_path, filename)
                if not os.path.isfile(file_path):
                    continue

                result = self._check_file_permissions(file_path)
                results.append(result)

        except (PermissionError, OSError):
            pass

        return results

    def run(self) -> CheckResult:
        """Execute the GRUB permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check GRUB configuration files
        file_results = []
        for file_path in self._get_grub_files():
            result = self._check_file_permissions(file_path)
            if result["exists"]:
                file_results.append(result)

        # Check GRUB directories
        dir_results = []
        for dir_path in self._get_grub_dirs():
            result = self._check_directory_permissions(dir_path)
            if result["exists"]:
                dir_results.append(result)

        # Check files in /etc/grub.d
        grub_d_results = self._check_grub_d_files()

        # Collect all issues
        files_with_issues = [r for r in file_results if r["issues"]]
        dirs_with_issues = [r for r in dir_results if r["issues"]]
        grub_d_with_issues = [r for r in grub_d_results if r["issues"]]

        details = {
            "file_results": file_results,
            "dir_results": dir_results,
            "grub_d_results": grub_d_results,
            "files_with_issues": files_with_issues,
            "dirs_with_issues": dirs_with_issues,
            "grub_d_with_issues": grub_d_with_issues,
        }

        # If no GRUB files found at all, that's a problem
        if not file_results and not dir_results:
            install_cmd = self._platform_install_packages_command("grub2")
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No GRUB configuration files or directories found",
                remediation=f"Verify GRUB is installed: {install_cmd}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if all existing files have proper permissions
        all_issues = files_with_issues + dirs_with_issues + grub_d_with_issues

        if not all_issues:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="All GRUB configuration files and directories have correct permissions",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issue_summary = []
        if files_with_issues:
            issue_summary.append(f"{len(files_with_issues)} config file(s) with incorrect permissions")
        if dirs_with_issues:
            issue_summary.append(f"{len(dirs_with_issues)} directory(ies) with incorrect permissions")
        if grub_d_with_issues:
            issue_summary.append(f"{len(grub_d_with_issues)} grub.d file(s) with incorrect permissions")

        message = "; ".join(issue_summary)

        # Build remediation
        remediation_parts = ["Fix GRUB file and directory permissions:", ""]

        if files_with_issues:
            remediation_parts.append("GRUB configuration files:")
            for r in files_with_issues:
                remediation_parts.append(f"  {r['path']}:")
                remediation_parts.append(f"    Current: {r.get('mode_string', 'unknown')}")
                remediation_parts.append(f"    Issues: {', '.join(r['issues'])}")
                remediation_parts.append(f"    Fix: sudo chmod 600 {r['path']}")
                if not r.get("is_root_owned", True):
                    remediation_parts.append(f"    Fix ownership: sudo chown root:root {r['path']}")
                remediation_parts.append("")

        if dirs_with_issues:
            remediation_parts.append("GRUB directories:")
            for r in dirs_with_issues:
                remediation_parts.append(f"  {r['path']}:")
                remediation_parts.append(f"    Current: {r.get('mode_string', 'unknown')}")
                remediation_parts.append(f"    Issues: {', '.join(r['issues'])}")
                remediation_parts.append(f"    Fix: sudo chmod 700 {r['path']}")
                if not r.get("is_root_owned", True):
                    remediation_parts.append(f"    Fix ownership: sudo chown root:root {r['path']}")
                remediation_parts.append("")

        if grub_d_with_issues:
            remediation_parts.append("GRUB configuration scripts (/etc/grub.d):")
            for r in grub_d_with_issues[:5]:  # Limit output
                remediation_parts.append(f"  {r['path']}:")
                remediation_parts.append(f"    Current: {r.get('mode_string', 'unknown')}")
                remediation_parts.append(f"    Fix: sudo chmod 600 {r['path']}")
                remediation_parts.append("")
            if len(grub_d_with_issues) > 5:
                remediation_parts.append(f"  ... and {len(grub_d_with_issues) - 5} more files")
            remediation_parts.append("")

        quick_file_paths = [r["path"] for r in file_results]
        quick_dir_paths = [r["path"] for r in dir_results]

        if quick_file_paths or quick_dir_paths:
            remediation_parts.append("Quick fix for detected GRUB paths:")
            for path in quick_file_paths:
                remediation_parts.append(f"  sudo chmod 600 {path}")
            for path in quick_dir_paths:
                remediation_parts.append(f"  sudo chmod 700 {path}")
            for path in quick_file_paths:
                remediation_parts.append(f"  sudo chown root:root {path}")
            for path in quick_dir_paths:
                remediation_parts.append(f"  sudo chown -R root:root {path}")
            remediation_parts.append("")

        remediation_parts.extend([
            "Note: 600 = rw------- (owner only)",
            "      700 = rwx------ (owner only for directories)",
            "",
            "CIS Benchmark: 1.3.2 - Ensure permissions on bootloader config are configured",
        ])

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=message,
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
