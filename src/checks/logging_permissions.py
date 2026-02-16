"""
CIS Audit Check: Log File Permissions

Checks that log files in /var/log have appropriate permissions
and ownership to prevent unauthorized access.
"""

import grp
import os
import pwd
import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class LogPermissionsCheck(BaseCheck):
    """Check for proper log file permissions and ownership."""

    id = "logging_permissions"
    name = "Log File Permissions"
    description = (
        "Verifies that log files in /var/log are not world-readable "
        "and are owned by root or appropriate system users"
    )
    severity = Severity.MEDIUM
    requires_root = True

    LOG_DIR = "/var/log"
    MAX_PERMISSIONS = 0o640  # Maximum allowed permissions (rw-r----)
    VALID_OWNERS = {"root"}
    VALID_GROUPS = {"root", "adm", "syslog", "systemd-journal"}

    def _check_file_permissions(self, file_path: Path) -> dict:
        """Check permissions and ownership of a single file.

        Args:
            file_path: Path to the file to check

        Returns:
            Dictionary with check results for this file
        """
        try:
            file_stat = file_path.stat()
            mode = stat.S_IMODE(file_stat.st_mode)

            # Get owner and group names
            try:
                owner = pwd.getpwuid(file_stat.st_uid).pw_name
                group = grp.getgrgid(file_stat.st_gid).gr_name
            except (KeyError, ImportError):
                owner = str(file_stat.st_uid)
                group = str(file_stat.st_gid)

            return {
                "path": str(file_path),
                "mode": oct(mode),
                "mode_int": mode,
                "owner": owner,
                "group": group,
                "world_readable": bool(mode & stat.S_IROTH),
                "world_writable": bool(mode & stat.S_IWOTH),
                "world_executable": bool(mode & stat.S_IXOTH),
                "valid_owner": owner in self.VALID_OWNERS,
                "valid_group": group in self.VALID_GROUPS,
            }
        except (OSError, IOError) as e:
            return {
                "path": str(file_path),
                "error": str(e),
            }

    def run(self) -> CheckResult:
        """Execute the log permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "log_dir": self.LOG_DIR,
            "files_checked": 0,
            "files_with_issues": [],
            "errors": [],
        }

        # Check if /var/log exists
        if not os.path.isdir(self.LOG_DIR):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Log directory {self.LOG_DIR} does not exist",
                remediation=(
                    "Verify system logging configuration. "
                    "The /var/log directory should exist on a standard Fedora system."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        files_checked = 0

        # Check files in /var/log
        try:
            for entry in os.scandir(self.LOG_DIR):
                if entry.is_file() or entry.is_symlink():
                    # Skip symlinks that point to non-existent targets
                    if entry.is_symlink() and not os.path.exists(entry.path):
                        continue

                    files_checked += 1
                    result = self._check_file_permissions(Path(entry.path))

                    if "error" in result:
                        details["errors"].append(result)
                        continue

                    file_issues = []

                    # Check world readability
                    if result["world_readable"]:
                        file_issues.append("world-readable")

                    # Check world writability (critical)
                    if result["world_writable"]:
                        file_issues.append("world-writable")

                    # Check world executability
                    if result["world_executable"]:
                        file_issues.append("world-executable")

                    # Check ownership
                    if not result["valid_owner"]:
                        file_issues.append(f"owner={result['owner']}")

                    if file_issues:
                        result["issues"] = file_issues
                        details["files_with_issues"].append(result)
                        issues.append(f"{result['path']}: {', '.join(file_issues)}")

        except (OSError, IOError) as e:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Failed to scan {self.LOG_DIR}: {str(e)}",
                remediation="Check directory permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        details["files_checked"] = files_checked

        # Determine result
        if issues:
            # Critical issue: world-writable log files
            world_writable = [
                f for f in details["files_with_issues"]
                if "world-writable" in f.get("issues", [])
            ]

            if world_writable:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message=f"Found {len(world_writable)} world-writable log files (critical security issue)",
                    remediation=(
                        "Fix world-writable log files immediately:\n"
                        "1. Identify affected files (see details)\n"
                        "2. Fix permissions: chmod 640 <file>\n"
                        "3. Verify ownership: chown root:root <file>\n"
                        "4. Check for compromised system"
                    ),
                    severity=Severity.HIGH,
                    requires_root=self.requires_root,
                    details=details,
                )

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Found {len(issues)} log files with permission issues",
                remediation=(
                    "Fix log file permissions:\n"
                    "1. Review affected files (see details)\n"
                    "2. Remove world-readable permissions: chmod o-rwx <file>\n"
                    "3. Set proper ownership: chown root:root <file> or chown root:adm <file>\n"
                    "4. Recommended permissions: 640 (rw-r-----)"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {files_checked} log files in {self.LOG_DIR} have appropriate permissions",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
