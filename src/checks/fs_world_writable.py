"""
CIS Audit Check: World-Writable Files

Finds world-writable files outside of /tmp and /var/tmp,
and checks for files without sticky bit in appropriate directories.
"""

import os
import stat
import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class WorldWritableFilesCheck(BaseCheck):
    """Check for world-writable files outside temporary directories."""

    id = "fs_world_writable"
    name = "World-Writable Files"
    description = (
        "Finds world-writable files outside of /tmp and /var/tmp, "
        "and checks for directories without sticky bit that should have it"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Directories to exclude from the search
    EXCLUDE_DIRS = {
        "/tmp",
        "/var/tmp",
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/boot",
        "/media",
        "/mnt",
    }

    # Directories that should have sticky bit if world-writable
    STICKY_BIT_DIRS = {
        "/tmp",
        "/var/tmp",
        "/var/spool/mail",
        "/var/spool/uucppublic",
        "/var/spool/samba",
        "/var/spool/cron",
    }

    def _find_world_writable_files(self) -> list[dict]:
        """Find world-writable files using find command.

        Returns:
            List of dictionaries with file information
        """
        files = []
        
        # Build find command with exclusions
        exclude_args = []
        for exclude_dir in self.EXCLUDE_DIRS:
            exclude_args.extend(["-path", exclude_dir, "-prune", "-o"])

        try:
            # Use find to locate world-writable files
            cmd = [
                "find", "/",
                *exclude_args,
                "-type", "f",
                "-perm", "-002",
                "-print"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            # Process results (even with non-zero exit, we may have partial results)
            for line in result.stdout.splitlines():
                filepath = line.strip()
                if not filepath:
                    continue
                    
                try:
                    stat_info = os.stat(filepath)
                    mode = stat_info.st_mode
                    
                    files.append({
                        "path": filepath,
                        "mode": oct(mode & 0o7777),
                        "mode_string": stat.filemode(mode),
                        "owner": stat_info.st_uid,
                        "group": stat_info.st_gid,
                    })
                except (OSError, PermissionError):
                    # Skip files we can't stat
                    pass
                    
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # find command not available
            pass
            
        return files

    def _find_world_writable_dirs_without_sticky(self) -> list[dict]:
        """Find world-writable directories without sticky bit.

        Returns:
            List of dictionaries with directory information
        """
        dirs = []
        
        # Build find command with exclusions
        exclude_args = []
        for exclude_dir in self.EXCLUDE_DIRS:
            exclude_args.extend(["-path", exclude_dir, "-prune", "-o"])

        try:
            # Use find to locate world-writable directories without sticky bit
            # -perm -002 = world writable
            # ! -perm -1000 = NOT sticky bit
            cmd = [
                "find", "/",
                *exclude_args,
                "-type", "d",
                "-perm", "-002",
                "!", "-perm", "-1000",
                "-print"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            for line in result.stdout.splitlines():
                dirpath = line.strip()
                if not dirpath:
                    continue
                    
                try:
                    stat_info = os.stat(dirpath)
                    mode = stat_info.st_mode
                    
                    dirs.append({
                        "path": dirpath,
                        "mode": oct(mode & 0o7777),
                        "mode_string": stat.filemode(mode),
                        "owner": stat_info.st_uid,
                        "group": stat_info.st_gid,
                        "should_have_sticky": dirpath in self.STICKY_BIT_DIRS,
                    })
                except (OSError, PermissionError):
                    pass
                    
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
            
        return dirs

    def _get_file_count_estimate(self) -> int:
        """Get a quick estimate of world-writable file count.

        Returns:
            Estimated count (may be -1 if unable to determine)
        """
        try:
            # Quick count using find with -printf and wc
            exclude_args = []
            for exclude_dir in self.EXCLUDE_DIRS:
                exclude_args.extend(["-path", exclude_dir, "-prune", "-o"])
            
            cmd = [
                "find", "/",
                *exclude_args,
                "-type", "f",
                "-perm", "-002",
                "-printf", "."
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return len(result.stdout)
        except:
            return -1

    def run(self) -> CheckResult:
        """Execute the world-writable files check.

        Returns:
            CheckResult with the outcome of the check
        """
        world_writable_files = self._find_world_writable_files()
        world_writable_dirs = self._find_world_writable_dirs_without_sticky()
        
        # Filter to directories that should have sticky bit
        critical_dirs = [
            d for d in world_writable_dirs 
            if d.get("should_have_sticky", False)
        ]
        other_dirs = [
            d for d in world_writable_dirs 
            if not d.get("should_have_sticky", False)
        ]

        details = {
            "world_writable_files_count": len(world_writable_files),
            "world_writable_files_sample": world_writable_files[:10],
            "world_writable_dirs_without_sticky_count": len(world_writable_dirs),
            "critical_dirs_without_sticky": critical_dirs,
            "other_dirs_without_sticky": other_dirs[:10],
        }

        # Determine result
        has_issues = bool(world_writable_files or critical_dirs)
        
        if not has_issues:
            message = "No world-writable files found outside temporary directories"
            if other_dirs:
                message += f"; {len(other_dirs)} world-writable directories without sticky bit (non-critical)"
            
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=message,
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if world_writable_files:
            issues.append(
                f"{len(world_writable_files)} world-writable files found"
            )
        if critical_dirs:
            issues.append(
                f"{len(critical_dirs)} critical directories missing sticky bit"
            )

        # Build remediation
        remediation_parts = ["Address world-writable files:"]
        
        if world_writable_files:
            remediation_parts.extend([
                "",
                "World-writable files:",
                "1. Review each file: ls -la <filepath>",
                "2. Remove if unnecessary: sudo rm <filepath>",
                "3. Or fix permissions: sudo chmod o-w <filepath>",
                "4. Consider using groups for shared access instead of world-writable",
            ])
        
        if critical_dirs:
            remediation_parts.extend([
                "",
                "Directories missing sticky bit:",
                "1. Set sticky bit: sudo chmod +t <directory>",
                "2. Verify: ls -ld <directory>",
            ])
            for d in critical_dirs:
                remediation_parts.append(f"   - {d['path']}: sudo chmod +t {d['path']}")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
