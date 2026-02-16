"""
CIS Audit Check: No Ungrouped Files or Directories (6.1.13)

Ensures that no ungrouped files or directories exist on the system.
Files not belonging to any group may be a sign of tampering or incomplete cleanup.

Note: This check is marked as expensive because it requires a full
filesystem scan which can take significant time on large systems.
CIS 6.1.13
"""

import subprocess
from pathlib import Path
from src.core.check import BaseCheck, CheckResult, Severity


class FSUngroupedFilesCheck(BaseCheck):
    """Check for ungrouped files and directories.
    
    Note: This check is marked as expensive because it performs a full
    filesystem scan which can take significant time on large systems.
    Use --full or --include-expensive flag to run this check.
    """

    id = "fs_ungrouped_files"
    name = "No Ungrouped Files or Directories"
    description = (
        "Scans the filesystem for files and directories that do not "
        "belong to any valid group. Ungrouped files may indicate tampering "
        "or incomplete cleanup."
    )
    severity = Severity.MEDIUM
    requires_root = True
    expensive = True  # Full filesystem scan is expensive

    # Directories to exclude from scan (performance optimization)
    EXCLUDE_DIRS = [
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/boot/efi",  # EFI partition may have different ownership
        "/mnt",
        "/media",
        "/tmp",
        "/var/tmp",
        "/var/lib/nfs/rpc_pipefs",
        "/var/lib/containers",  # Container storage
        "/var/lib/docker",      # Docker storage
    ]

    # Maximum number of ungrouped files to report
    MAX_REPORT = 50

    def _find_ungrouped_files(self) -> list[dict]:
        """Find files not belonging to any group.
        
        Returns:
            List of dictionaries containing file information
        """
        ungrouped_files = []

        try:
            # Build find command with exclusions
            exclude_args = []
            for exclude_dir in self.EXCLUDE_DIRS:
                exclude_args.extend(["-path", exclude_dir, "-prune", "-o"])

            # Run find command to locate ungrouped files
            cmd = [
                "find", "/",
                *exclude_args,
                "-nogroup",
                "-print"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if result.returncode == 0 or result.stdout:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if not line:
                        continue

                    file_path = Path(line)
                    if file_path.exists():
                        try:
                            stat = file_path.stat()
                            ungrouped_files.append({
                                "path": str(file_path),
                                "uid": stat.st_uid,
                                "gid": stat.st_gid,
                                "size": stat.st_size,
                            })
                        except (OSError, PermissionError):
                            ungrouped_files.append({
                                "path": str(file_path),
                                "uid": None,
                                "gid": None,
                                "size": None,
                            })

                    if len(ungrouped_files) >= self.MAX_REPORT:
                        break

        except subprocess.TimeoutExpired:
            return [{"error": "Filesystem scan timed out"}]
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            return [{"error": f"Failed to run find command: {str(e)}"}]

        return ungrouped_files

    def run(self) -> CheckResult:
        """Execute the ungrouped files check.

        Returns:
            CheckResult with the outcome of the check
        """
        ungrouped_files = self._find_ungrouped_files()

        # Check for errors
        if ungrouped_files and "error" in ungrouped_files[0]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Failed to scan for ungrouped files: {ungrouped_files[0]['error']}",
                remediation="Ensure find command is available and filesystem is accessible",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"error": ungrouped_files[0]["error"]},
            )

        if not ungrouped_files:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="No ungrouped files or directories found",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "ungrouped_count": 0,
                    "excluded_dirs": self.EXCLUDE_DIRS,
                },
            )

        # Found ungrouped files
        file_list = [f["path"] for f in ungrouped_files[:10]]
        sample_text = "\n".join([f"  - {path}" for path in file_list])

        total_count = len(ungrouped_files)
        truncated = total_count >= self.MAX_REPORT

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"Found {total_count}+ ungrouped files/directories" if truncated
                else f"Found {total_count} ungrouped files/directories"
            ),
            remediation=(
                f"Review and fix group ownership of ungrouped files:\n"
                f"Sample ungrouped files:\n{sample_text}\n\n"
                f"To fix group ownership, either:\n"
                f"1. Delete the files if they are not needed:\n"
                f"   sudo find / -nogroup -delete\n\n"
                f"2. Change group ownership to a valid group:\n"
                f"   sudo find / -nogroup -exec chown root:root {{}} \\;\n\n"
                f"Note: Review files before making changes. "
                f"Some ungrouped files may be intentional."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "ungrouped_count": total_count,
                "truncated": truncated,
                "ungrouped_files": ungrouped_files,
                "excluded_dirs": self.EXCLUDE_DIRS,
            },
        )
