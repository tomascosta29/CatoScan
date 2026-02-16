"""
CIS Audit Check: /tmp Mount Options

Checks if /tmp is mounted with noexec, nosuid, and nodev options.
"""

import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class TmpMountCheck(BaseCheck):
    """Check for /tmp mount options (noexec, nosuid, nodev)."""

    id = "fs_tmp_mount"
    name = "/tmp Mount Options"
    description = (
        "Verifies that /tmp is mounted with noexec, nosuid, and nodev "
        "options to prevent execution of malicious code"
    )
    severity = Severity.HIGH
    requires_root = True

    REQUIRED_OPTIONS = {"noexec", "nosuid", "nodev"}

    def _get_mount_info(self) -> dict:
        """Get mount information for /tmp.

        Returns:
            Dictionary with mount options and fstab entry
        """
        info = {
            "mounted": False,
            "mount_options": [],
            "fstab_entry": None,
            "filesystem_type": None,
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
                    if " on /tmp " in line:
                        info["mounted"] = True
                        # Parse mount options from line like:
                        # /dev/sda1 on /tmp type ext4 (rw,noexec,nosuid,nodev)
                        if "(" in line and ")" in line:
                            options_str = line.split("(")[1].split(")")[0]
                            info["mount_options"] = options_str.split(",")
                        # Get filesystem type
                        if " type " in line:
                            parts = line.split(" type ")
                            if len(parts) > 1:
                                info["filesystem_type"] = parts[1].split()[0]
                        break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Check /etc/fstab for /tmp entry
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
                        if len(parts) >= 4 and parts[1] == "/tmp":
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

    def _check_tmp_mount_options(self, mount_info: dict) -> tuple[bool, set, set]:
        """Check if /tmp has required mount options.

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
        """Check if /etc/fstab has required options for /tmp.

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
        """Execute the /tmp mount options check.

        Returns:
            CheckResult with the outcome of the check
        """
        mount_info = self._get_mount_info()

        # Check if /tmp is mounted
        if not mount_info["mounted"]:
            # Check if it's defined in fstab but not mounted
            if mount_info["fstab_entry"]:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="/tmp is defined in /etc/fstab but not currently mounted",
                    remediation=(
                        "Mount /tmp filesystem:\n"
                        "1. Check fstab entry: grep /tmp /etc/fstab\n"
                        "2. Mount /tmp: sudo mount /tmp\n"
                        "3. Verify: mount | grep /tmp"
                    ),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=mount_info,
                )
            else:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="/tmp is not mounted as a separate filesystem",
                    remediation=(
                        "Configure /tmp as a separate mount with security options:\n"
                        "1. Create a partition or tmpfs for /tmp\n"
                        "2. Add to /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0\n"
                        "3. Mount /tmp: sudo mount /tmp\n"
                        "4. Verify: mount | grep /tmp"
                    ),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=mount_info,
                )

        # Check current mount options
        mount_ok, mount_present, mount_missing = self._check_tmp_mount_options(mount_info)
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
                    f"/tmp is mounted with all required security options: "
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
                issues.append("No /tmp entry in /etc/fstab")

        # Build remediation
        remediation_parts = [
            "Configure /tmp with required mount options (noexec, nosuid, nodev):"
        ]
        
        if not mount_info["fstab_entry"]:
            remediation_parts.append(
                "1. Add to /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0"
            )
        else:
            remediation_parts.append(
                "1. Update /etc/fstab to include: noexec,nosuid,nodev"
            )
        
        remediation_parts.extend([
            "2. Remount /tmp: sudo mount -o remount /tmp",
            "3. Verify: mount | grep /tmp",
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
