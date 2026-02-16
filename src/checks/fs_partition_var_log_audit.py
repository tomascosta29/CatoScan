"""
CIS Audit Check: /var/log/audit Partition

Checks if /var/log/audit is mounted as a separate partition (CIS 1.1.8).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class VarLogAuditPartitionCheck(BaseCheck):
    """Check if /var/log/audit is mounted as a separate partition."""

    id = "fs_partition_var_log_audit"
    name = "/var/log/audit Partition"
    description = (
        "Verifies that /var/log/audit is mounted as a separate partition "
        "to prevent audit logs from filling the root or /var filesystem"
    )
    severity = Severity.HIGH
    requires_root = True

    def _get_mount_info(self) -> dict:
        """Get mount information for /var/log/audit.

        Returns:
            Dictionary with mount options and fstab entry
        """
        info = {
            "mounted": False,
            "mount_options": [],
            "fstab_entry": None,
            "filesystem_type": None,
            "mount_source": None,
        }

        # Check current mount options using mount command
        try:
            result = subprocess.run(
                ["mount"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if " on /var/log/audit " in line:
                        info["mounted"] = True
                        # Parse mount options from line like:
                        # /dev/sda1 on /var/log/audit type ext4 (rw,relatime)
                        parts = line.split()
                        if len(parts) >= 1:
                            info["mount_source"] = parts[0]
                        if "(" in line and ")" in line:
                            options_str = line.split("(")[1].split(")")[0]
                            info["mount_options"] = options_str.split(",")
                        # Get filesystem type
                        if " type " in line:
                            type_parts = line.split(" type ")
                            if len(type_parts) > 1:
                                info["filesystem_type"] = type_parts[1].split()[0]
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Also check /proc/mounts for more reliable parsing
        try:
            proc_mounts = Path("/proc/mounts")
            if proc_mounts.exists():
                with open(proc_mounts, "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[1] == "/var/log/audit":
                            info["mounted"] = True
                            info["mount_source"] = parts[0]
                            info["filesystem_type"] = parts[2]
                            info["mount_options"] = parts[3].split(",")
                            break
        except (PermissionError, OSError):
            pass

        # Check /etc/fstab for /var/log/audit entry
        fstab_path = Path("/etc/fstab")
        if fstab_path.exists():
            try:
                with open(fstab_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 4 and parts[1] == "/var/log/audit":
                            info["fstab_entry"] = {
                                "device": parts[0],
                                "mount_point": parts[1],
                                "filesystem_type": parts[2],
                                "options": parts[3].split(","),
                            }
                            if len(parts) >= 6:
                                info["fstab_entry"]["dump"] = parts[4]
                                info["fstab_entry"]["pass"] = parts[5]
                            break
            except (PermissionError, OSError):
                pass

        return info

    def run(self) -> CheckResult:
        """Execute the /var/log/audit partition check.

        Returns:
            CheckResult with the outcome of the check
        """
        mount_info = self._get_mount_info()

        # Check if /var/log/audit is mounted as a separate partition
        if mount_info["mounted"]:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"/var/log/audit is mounted as a separate partition "
                    f"({mount_info.get('mount_source', 'unknown')}, "
                    f"{mount_info.get('filesystem_type', 'unknown')})"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=mount_info,
            )

        # Check if it's defined in fstab but not mounted
        if mount_info["fstab_entry"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="/var/log/audit is defined in /etc/fstab but not currently mounted",
                remediation=(
                    "Mount /var/log/audit filesystem:\n"
                    "1. Check fstab entry: grep /var/log/audit /etc/fstab\n"
                    "2. Mount /var/log/audit: sudo mount /var/log/audit\n"
                    "3. Verify: mount | grep 'on /var/log/audit '"                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=mount_info,
            )

        # /var/log/audit is not a separate partition
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="/var/log/audit is not mounted as a separate partition",
            remediation=(
                "Configure /var/log/audit as a separate partition:\n"
                "1. Create a dedicated partition for /var/log/audit during installation or using LVM\n"
                "2. Add to /etc/fstab (example):\n"
                "   /dev/sdXn /var/log/audit ext4 defaults,nodev,nosuid,noexec 0 2\n"
                "3. Mount /var/log/audit: sudo mount /var/log/audit\n"
                "4. Verify: mount | grep 'on /var/log/audit '\n\n"
                "Note: This requires planning during system installation or maintenance mode.\n"
                "      Separating /var/log/audit prevents audit logs from filling other filesystems.\n"
                "      Audit logs can grow very large in high-security environments."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=mount_info,
        )
