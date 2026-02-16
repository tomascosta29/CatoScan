"""
CIS Audit Check: Home Directory Permissions

Checks home directory permissions to ensure they are not
world-readable or world-writable.
"""

import os
import pwd
import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class HomePermissionsCheck(BaseCheck):
    """Check home directory permissions for all users."""

    id = "fs_home_permissions"
    name = "Home Directory Permissions"
    description = (
        "Verifies that user home directories are not world-readable "
        "or world-writable, including /root"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # System users to skip (UID < 1000 typically)
    SYSTEM_USER_MAX_UID = 999

    # Common system home directories to check but not fail on
    SYSTEM_HOMES = {
        "/root",
    }

    def _is_safe_home_path(self, home: str) -> bool:
        """Validate home path from passwd entries."""
        if not home:
            return False
        if any(char in home for char in ("\x00", "\n", "\r", "\t")):
            return False
        home_path = Path(home)
        if not home_path.is_absolute():
            return False
        if ".." in home_path.parts:
            return False
        return True

    def _get_all_users(self) -> tuple[list[pwd.struct_passwd], list[str]]:
        """Get all users from /etc/passwd.

        Returns:
            Tuple of (pwd entries, diagnostics)
        """
        users = []
        diagnostics: list[str] = []
        try:
            for user in pwd.getpwall():
                # Skip system users (typically UID < 1000)
                # But include root and any user with a real home directory
                if not self._is_safe_home_path(user.pw_dir):
                    diagnostics.append(f"Skipped unsafe home path for user '{user.pw_name}': {user.pw_dir}")
                    continue

                if user.pw_uid >= self.SYSTEM_USER_MAX_UID or user.pw_dir in self.SYSTEM_HOMES:
                    users.append(user)
        except OSError as e:
            diagnostics.append(f"Failed to enumerate passwd entries: {type(e).__name__}: {e}")
        return users, diagnostics

    def _check_home_directory(self, user: pwd.struct_passwd) -> dict:
        """Check permissions of a single home directory.

        Args:
            user: pwd entry for the user

        Returns:
            Dictionary with check results
        """
        result = {
            "username": user.pw_name,
            "uid": user.pw_uid,
            "home": user.pw_dir,
            "exists": False,
            "is_directory": False,
            "mode": None,
            "mode_string": None,
            "owner_match": False,
            "world_readable": False,
            "world_writable": False,
            "world_executable": False,
            "group_readable": False,
            "group_writable": False,
            "issues": [],
        }

        home_path = Path(user.pw_dir)
        
        if not home_path.exists():
            result["issues"].append("home directory does not exist")
            return result

        result["exists"] = True

        if not home_path.is_dir():
            result["is_directory"] = False
            result["issues"].append("home path is not a directory")
            return result

        result["is_directory"] = True

        try:
            stat_info = home_path.stat()
            mode = stat_info.st_mode
            
            result["mode"] = oct(mode & 0o7777)
            result["mode_string"] = stat.filemode(mode)
            result["owner_match"] = (stat_info.st_uid == user.pw_uid)
            
            # Check world permissions
            result["world_readable"] = bool(mode & stat.S_IROTH)
            result["world_writable"] = bool(mode & stat.S_IWOTH)
            result["world_executable"] = bool(mode & stat.S_IXOTH)
            
            # Check group permissions
            result["group_readable"] = bool(mode & stat.S_IRGRP)
            result["group_writable"] = bool(mode & stat.S_IWGRP)
            
            # Determine issues
            if result["world_readable"]:
                result["issues"].append("world-readable")
            if result["world_writable"]:
                result["issues"].append("world-writable")
            if not result["owner_match"]:
                result["issues"].append("owner does not match user")
                
        except (PermissionError, OSError) as e:
            result["issues"].append(f"cannot stat: {str(e)}")

        return result

    def _check_root_home(self) -> dict:
        """Check /root directory specifically.

        Returns:
            Dictionary with check results
        """
        result = {
            "username": "root",
            "uid": 0,
            "home": "/root",
            "exists": False,
            "is_directory": False,
            "mode": None,
            "mode_string": None,
            "world_readable": False,
            "world_writable": False,
            "world_executable": False,
            "issues": [],
        }

        root_path = Path("/root")
        
        if not root_path.exists():
            result["issues"].append("/root does not exist")
            return result

        result["exists"] = True

        if not root_path.is_dir():
            result["issues"].append("/root is not a directory")
            return result

        result["is_directory"] = True

        try:
            stat_info = root_path.stat()
            mode = stat_info.st_mode
            
            result["mode"] = oct(mode & 0o7777)
            result["mode_string"] = stat.filemode(mode)
            
            # Check world permissions - /root should have no world access
            result["world_readable"] = bool(mode & stat.S_IROTH)
            result["world_writable"] = bool(mode & stat.S_IWOTH)
            result["world_executable"] = bool(mode & stat.S_IXOTH)
            
            # /root should be 700 or more restrictive
            if result["world_readable"]:
                result["issues"].append("world-readable")
            if result["world_writable"]:
                result["issues"].append("world-writable")
            if result["world_executable"]:
                result["issues"].append("world-executable")
                
        except (PermissionError, OSError) as e:
            result["issues"].append(f"cannot stat: {str(e)}")

        return result

    def run(self) -> CheckResult:
        """Execute the home directory permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check /root first
        root_check = self._check_root_home()
        
        # Check all user home directories
        users, user_diagnostics = self._get_all_users()
        user_checks = []
        
        for user in users:
            # Skip if we already checked /root
            if user.pw_dir == "/root":
                continue
            check = self._check_home_directory(user)
            user_checks.append(check)

        # Collect issues
        root_issues = root_check.get("issues", [])
        users_with_issues = [
            c for c in user_checks 
            if c.get("issues") and "does not exist" not in c["issues"][0]
        ]

        details = {
            "root_check": root_check,
            "user_checks": user_checks,
            "users_checked": len(user_checks),
            "users_with_issues": users_with_issues,
            "diagnostics": user_diagnostics,
        }

        # Determine if there are real issues
        # Skip "does not exist" for users who may not have created their home yet
        significant_root_issues = [
            i for i in root_issues 
            if "does not exist" not in i
        ]
        significant_user_issues = [
            c for c in users_with_issues
            if not all("does not exist" in i for i in c.get("issues", []))
        ]

        has_issues = bool(significant_root_issues or significant_user_issues)

        if not has_issues:
            message_parts = []
            if not root_issues:
                message_parts.append("/root permissions are correct")
            if not significant_user_issues:
                message_parts.append(f"{len(user_checks)} user home directories have correct permissions")
            
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="; ".join(message_parts) if message_parts else "All home directories have correct permissions",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if significant_root_issues:
            issues.append(f"/root: {', '.join(significant_root_issues)}")
        
        # Group user issues
        world_readable_homes = [
            c for c in significant_user_issues 
            if "world-readable" in c.get("issues", [])
        ]
        world_writable_homes = [
            c for c in significant_user_issues 
            if "world-writable" in c.get("issues", [])
        ]
        
        if world_readable_homes:
            issues.append(f"{len(world_readable_homes)} homes world-readable")
        if world_writable_homes:
            issues.append(f"{len(world_writable_homes)} homes world-writable")

        # Build remediation
        remediation_parts = ["Fix home directory permissions:", ""]
        
        if significant_root_issues:
            remediation_parts.extend([
                "/root directory:",
                f"  Current: {root_check.get('mode_string', 'unknown')}",
                "  Fix: sudo chmod 700 /root",
                "  Verify: ls -ld /root",
                "",
            ])
        
        if world_readable_homes:
            remediation_parts.extend([
                "World-readable home directories (remove world read access):",
            ])
            for c in world_readable_homes[:5]:
                remediation_parts.append(
                    f"  - {c['username']}: sudo chmod o-r {c['home']}"
                )
            if len(world_readable_homes) > 5:
                remediation_parts.append(f"  ... and {len(world_readable_homes) - 5} more")
            remediation_parts.append("")
        
        if world_writable_homes:
            remediation_parts.extend([
                "World-writable home directories (remove world write access):",
            ])
            for c in world_writable_homes[:5]:
                remediation_parts.append(
                    f"  - {c['username']}: sudo chmod o-w {c['home']}"
                )
            if len(world_writable_homes) > 5:
                remediation_parts.append(f"  ... and {len(world_writable_homes) - 5} more")
            remediation_parts.append("")
        
        remediation_parts.extend([
            "General fix for all users:",
            "  sudo chmod 700 /home/*",
            "  sudo chmod 700 /root",
            "",
            "Note: 700 = rwx------ (owner only)",
            "      755 = rwxr-xr-x (world readable - NOT recommended for homes)",
        ])

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
