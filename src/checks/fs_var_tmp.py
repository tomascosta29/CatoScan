"""
CIS Audit Check: /var/tmp Permissions

Checks /var/tmp permissions and verifies the sticky bit is set.
"""

import os
import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class VarTmpPermissionsCheck(BaseCheck):
    """Check for /var/tmp permissions and sticky bit."""

    id = "fs_var_tmp"
    name = "/var/tmp Permissions"
    description = (
        "Verifies that /var/tmp has appropriate permissions (1777) "
        "and the sticky bit is set to prevent users from deleting "
        "files owned by other users"
    )
    severity = Severity.MEDIUM
    requires_root = True

    EXPECTED_MODE = 0o1777  # drwxrwxrwt with sticky bit

    def _get_var_tmp_info(self) -> dict:
        """Get information about /var/tmp.

        Returns:
            Dictionary with permissions and ownership info
        """
        info = {
            "exists": False,
            "path": "/var/tmp",
            "mode": None,
            "mode_octal": None,
            "mode_string": None,
            "owner": None,
            "group": None,
            "sticky_bit_set": False,
            "world_writable": False,
            "world_readable": False,
            "world_executable": False,
        }

        var_tmp_path = Path("/var/tmp")
        
        if not var_tmp_path.exists():
            return info

        info["exists"] = True

        try:
            stat_info = var_tmp_path.stat()
            mode = stat_info.st_mode
            
            info["mode"] = mode
            info["mode_octal"] = oct(mode & 0o7777)
            info["mode_string"] = stat.filemode(mode)
            info["owner"] = stat_info.st_uid
            info["group"] = stat_info.st_gid
            
            # Check permission bits
            info["sticky_bit_set"] = bool(mode & stat.S_ISVTX)
            info["world_writable"] = bool(mode & stat.S_IWOTH)
            info["world_readable"] = bool(mode & stat.S_IROTH)
            info["world_executable"] = bool(mode & stat.S_IXOTH)
            
        except (PermissionError, OSError) as e:
            info["error"] = str(e)

        return info

    def _is_symlink(self) -> bool:
        """Check if /var/tmp is a symlink (e.g., to /tmp).

        Returns:
            True if /var/tmp is a symlink
        """
        try:
            return os.path.islink("/var/tmp")
        except OSError:
            return False

    def _get_symlink_target(self) -> str | None:
        """Get the target of /var/tmp symlink.

        Returns:
            Target path if symlink, None otherwise
        """
        try:
            return os.readlink("/var/tmp")
        except OSError:
            return None

    def run(self) -> CheckResult:
        """Execute the /var/tmp permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if /var/tmp is a symlink
        if self._is_symlink():
            target = self._get_symlink_target()
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"/var/tmp is a symlink to {target} - permissions inherited from target",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "is_symlink": True,
                    "target": target,
                },
            )

        info = self._get_var_tmp_info()

        # Check if /var/tmp exists
        if not info["exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="/var/tmp does not exist",
                remediation=(
                    "Create /var/tmp directory with proper permissions:\n"
                    "1. Create directory: sudo mkdir -p /var/tmp\n"
                    "2. Set permissions: sudo chmod 1777 /var/tmp\n"
                    "3. Set ownership: sudo chown root:root /var/tmp\n"
                    "4. Verify: ls -ld /var/tmp"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=info,
            )

        # Check for errors reading permissions
        if "error" in info:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cannot read /var/tmp permissions: {info['error']}",
                remediation="Verify /var/tmp exists and is accessible",
                severity=self.severity,
                requires_root=self.requires_root,
                details=info,
            )

        issues = []
        
        # Check sticky bit
        if not info["sticky_bit_set"]:
            issues.append("sticky bit not set")
        
        # Check world writable (should be world writable with sticky bit)
        if not info["world_writable"]:
            issues.append("not world-writable")
        
        # Check world executable (should be world executable)
        if not info["world_executable"]:
            issues.append("not world-executable")

        # Determine result
        if not issues:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"/var/tmp has correct permissions ({info['mode_string']}) "
                    f"with sticky bit set"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=info,
            )

        # Some issues found
        if not info["sticky_bit_set"]:
            # Critical issue: sticky bit not set
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"/var/tmp is missing required security settings: {', '.join(issues)}",
                remediation=(
                    "Fix /var/tmp permissions:\n"
                    "1. Set sticky bit and permissions: sudo chmod 1777 /var/tmp\n"
                    "2. Verify: ls -ld /var/tmp\n"
                    "Expected output: drwxrwxrwt (permissions 1777)"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=info,
            )
        else:
            # Sticky bit is set but other issues
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"/var/tmp has incorrect permissions: {', '.join(issues)}",
                remediation=(
                    "Fix /var/tmp permissions:\n"
                    f"1. Current mode: {info['mode_octal']}\n"
                    f"2. Set correct permissions: sudo chmod 1777 /var/tmp\n"
                    "3. Verify: ls -ld /var/tmp"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=info,
            )
