"""
CIS Audit Check: /dev/shm Mount Options

Checks if /dev/shm is mounted with nodev, nosuid, and noexec options (CIS 1.1.17-1.1.19).
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class DevShmMountCheck(BaseCheck):
    """Check for /dev/shm mount options (nodev, nosuid, noexec)."""

    id = "fs_dev_shm"
    name = "/dev/shm Mount Options"
    description = (
        "Verifies that /dev/shm is mounted with nodev, nosuid, and noexec "
        "options to prevent execution of malicious code and device file creation"
    )
    severity = Severity.MEDIUM
    requires_root = True

    REQUIRED_OPTIONS = {"nodev", "nosuid", "noexec"}

    def _get_mount_info(self) -> dict:
        """Get mount information for /dev/shm.

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
                    if " on /dev/shm " in line:
                        info["mounted"] = True
                        # Parse mount options from line like:
                        # tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec)
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
                        if len(parts) >= 4 and parts[1] == "/dev/shm":
                            info["mounted"] = True
                            info["mount_source"] = parts[0]
                            info["filesystem_type"] = parts[2]
                            info["mount_options"] = parts[3].split(",")
                            break
        except (PermissionError, OSError):
            pass

        # Check /etc/fstab for /dev/shm entry
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
                        if len(parts) >= 4 and parts[1] == "/dev/shm":
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

    def _check_mount_options(self, mount_info: dict) -> tuple[bool, set, set]:
        """Check if /dev/shm has required mount options.

        Args:
            mount_info: Dictionary with mount information

        Returns:
            Tuple of (all_present, present_options, missing_options)
        """
        current_options = set(mount_info.get("mount_options", []))
        present = self.REQUIRED_OPTIONS & current_options
        missing = self.REQUIRED_OPTIONS - current_options
        return len(missing) == 0, present, missing

    def _check_fstab_options(self, mount_info: dict) -> tuple[bool, set, set]:
        """Check if /etc/fstab has required options for /dev/shm.

        Args:
            mount_info: Dictionary with mount information

        Returns:
            Tuple of (all_present, present_options, missing_options)
        """
        fstab_entry = mount_info.get("fstab_entry")
        if not fstab_entry:
            return False, set(), self.REQUIRED_OPTIONS

        fstab_options = set(fstab_entry.get("options", []))
        present = self.REQUIRED_OPTIONS & fstab_options
        missing = self.REQUIRED_OPTIONS - fstab_options
        return len(missing) == 0, present, missing

    def run(self) -> CheckResult:
        """Execute the /dev/shm mount options check.

        Returns:
            CheckResult with the outcome of the check
        """
        mount_info = self._get_mount_info()

        # Check if /dev/shm is mounted
        if not mount_info["mounted"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="/dev/shm is not mounted",
                remediation=(
                    "Mount /dev/shm filesystem:\n"
                    "1. Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0\n"
                    "2. Mount /dev/shm: sudo mount /dev/shm\n"
                    "3. Verify: mount | grep /dev/shm"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=mount_info,
            )

        # Check current mount options
        mount_ok, mount_present, mount_missing = self._check_mount_options(mount_info)
        mount_info["mount_check"] = {
            "present": list(mount_present),
            "missing": list(mount_missing),
        }

        # Check fstab options
        fstab_ok, fstab_present, fstab_missing = self._check_fstab_options(mount_info)
        mount_info["fstab_check"] = {
            "present": list(fstab_present),
            "missing": list(fstab_missing),
        }

        # Determine overall result
        if mount_ok and fstab_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"/dev/shm is mounted with all required security options: "
                    f"{', '.join(sorted(self.REQUIRED_OPTIONS))}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=mount_info,
            )

        # Build failure message
        issues = []
        if not mount_ok:
            issues.append(
                f"Current mount missing: {', '.join(sorted(mount_missing))}"
            )
        if not fstab_ok:
            if mount_info["fstab_entry"]:
                issues.append(
                    f"fstab entry missing: {', '.join(sorted(fstab_missing))}"
                )
            else:
                issues.append("No /dev/shm entry in /etc/fstab")

        # Build remediation
        remediation_parts = [
            "Configure /dev/shm with required mount options (nodev, nosuid, noexec):"
        ]

        if not mount_info["fstab_entry"]:
            remediation_parts.append(
                "1. Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
            )
        else:
            remediation_parts.append(
                "1. Update /etc/fstab to include: nodev,nosuid,noexec"
            )

        remediation_parts.extend([
            "2. Remount /dev/shm: sudo mount -o remount /dev/shm",
            "3. Verify: mount | grep /dev/shm",
        ])

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(issues),
            remediation="\n".join(remediation_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=mount_info,
        )
