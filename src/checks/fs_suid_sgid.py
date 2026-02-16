"""
CIS Audit Check: SUID/SGID Files Audit

Finds files with SUID/SGID bits set and compares against a whitelist
of expected SUID files to flag unexpected ones.
"""

import os
import stat
import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SuidSgidAuditCheck(BaseCheck):
    """Audit SUID/SGID files and flag unexpected ones."""

    id = "fs_suid_sgid"
    name = "SUID/SGID Files Audit"
    description = (
        "Finds files with SUID/SGID bits set and compares against "
        "a whitelist of expected SUID files to flag unexpected ones"
    )
    severity = Severity.HIGH
    requires_root = True

    # Whitelist of expected SUID files on Fedora systems
    # These are standard system binaries that legitimately need SUID
    EXPECTED_SUID_FILES = {
        "/usr/bin/at",
        "/usr/bin/chage",
        "/usr/bin/chfn",
        "/usr/bin/chsh",
        "/usr/bin/crontab",
        "/usr/bin/fusermount",
        "/usr/bin/fusermount3",
        "/usr/bin/gpasswd",
        "/usr/bin/mount",
        "/usr/bin/newgrp",
        "/usr/bin/passwd",
        "/usr/bin/pkexec",
        "/usr/bin/ssh-agent",
        "/usr/bin/staprun",
        "/usr/bin/su",
        "/usr/bin/sudo",
        "/usr/bin/umount",
        "/usr/bin/write",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
        "/usr/lib/dbus-1/dbus-daemon-launch-helper",
        "/usr/libexec/polkit-1/polkit-agent-helper-1",
        "/usr/libexec/openssh/ssh-keysign",
        "/usr/libexec/sssd/krb5_child",
        "/usr/libexec/sssd/ldap_child",
        "/usr/libexec/sssd/selinux_child",
        "/usr/libexec/sssd/proxy_child",
        "/usr/sbin/pam_timestamp_check",
        "/usr/sbin/unix_chkpwd",
        "/usr/sbin/userhelper",
        "/usr/sbin/usernetctl",
        "/usr/sbin/mount.nfs",
        "/usr/sbin/mount.nfs4",
        "/usr/sbin/netreport",
        "/usr/lib/snapd/snap-confine",
        "/usr/bin/Xorg",  # May vary by installation
    }

    # Whitelist of expected SGID files
    EXPECTED_SGID_FILES = {
        "/usr/bin/crontab",
        "/usr/bin/ssh-agent",
        "/usr/bin/write",
        "/usr/libexec/utempter/utempter",
    }

    # Directories to exclude from search
    EXCLUDE_DIRS = {
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/boot",
    }

    def _find_suid_sgid_files(self) -> tuple[list[dict], list[dict]]:
        """Find all files with SUID or SGID bits set.

        Returns:
            Tuple of (suid_files, sgid_files)
        """
        suid_files = []
        sgid_files = []
        
        # Build find command with exclusions
        exclude_args = []
        for exclude_dir in self.EXCLUDE_DIRS:
            exclude_args.extend(["-path", exclude_dir, "-prune", "-o"])

        try:
            # Find SUID files (-perm -4000)
            cmd = [
                "find", "/",
                *exclude_args,
                "-type", "f",
                "-perm", "-4000",
                "-print"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            for line in result.stdout.splitlines():
                filepath = line.strip()
                if not filepath:
                    continue
                    
                try:
                    stat_info = os.stat(filepath)
                    mode = stat_info.st_mode
                    
                    suid_files.append({
                        "path": filepath,
                        "mode": oct(mode & 0o7777),
                        "mode_string": stat.filemode(mode),
                        "owner": stat_info.st_uid,
                        "group": stat_info.st_gid,
                    })
                except (OSError, PermissionError):
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            # Find SGID files (-perm -2000)
            cmd = [
                "find", "/",
                *exclude_args,
                "-type", "f",
                "-perm", "-2000",
                "-print"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            for line in result.stdout.splitlines():
                filepath = line.strip()
                if not filepath:
                    continue
                    
                try:
                    stat_info = os.stat(filepath)
                    mode = stat_info.st_mode
                    
                    sgid_files.append({
                        "path": filepath,
                        "mode": oct(mode & 0o7777),
                        "mode_string": stat.filemode(mode),
                        "owner": stat_info.st_uid,
                        "group": stat_info.st_gid,
                    })
                except (OSError, PermissionError):
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
            
        return suid_files, sgid_files

    def _check_against_whitelist(self, files: list[dict], whitelist: set) -> tuple[list[dict], list[dict]]:
        """Check files against whitelist.

        Args:
            files: List of file dictionaries
            whitelist: Set of expected file paths

        Returns:
            Tuple of (expected_files, unexpected_files)
        """
        expected = []
        unexpected = []
        
        for f in files:
            path = f["path"]
            # Normalize path for comparison
            normalized_path = os.path.normpath(path)
            
            if normalized_path in whitelist or path in whitelist:
                f["whitelisted"] = True
                expected.append(f)
            else:
                f["whitelisted"] = False
                unexpected.append(f)
                
        return expected, unexpected

    def run(self) -> CheckResult:
        """Execute the SUID/SGID audit check.

        Returns:
            CheckResult with the outcome of the check
        """
        suid_files, sgid_files = self._find_suid_sgid_files()
        
        # Check against whitelists
        expected_suid, unexpected_suid = self._check_against_whitelist(
            suid_files, self.EXPECTED_SUID_FILES
        )
        expected_sgid, unexpected_sgid = self._check_against_whitelist(
            sgid_files, self.EXPECTED_SGID_FILES
        )

        details = {
            "suid_files_count": len(suid_files),
            "sgid_files_count": len(sgid_files),
            "expected_suid_count": len(expected_suid),
            "expected_sgid_count": len(expected_sgid),
            "unexpected_suid": unexpected_suid,
            "unexpected_sgid": unexpected_sgid,
            "expected_suid_sample": expected_suid[:5],
            "expected_sgid_sample": expected_sgid[:5],
        }

        # Determine result
        has_unexpected = bool(unexpected_suid or unexpected_sgid)
        
        if not has_unexpected:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"All {len(suid_files)} SUID and {len(sgid_files)} SGID files "
                    f"are in the expected whitelist"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if unexpected_suid:
            issues.append(f"{len(unexpected_suid)} unexpected SUID files found")
        if unexpected_sgid:
            issues.append(f"{len(unexpected_sgid)} unexpected SGID files found")

        # Build remediation
        remediation_parts = [
            "Review unexpected SUID/SGID files - these may be security risks:",
            "",
        ]
        
        if unexpected_suid:
            remediation_parts.append("Unexpected SUID files:")
            for f in unexpected_suid:
                remediation_parts.append(f"  - {f['path']} ({f['mode_string']})")
            remediation_parts.extend([
                "",
                "To remove SUID bit:",
                "  sudo chmod u-s <filepath>",
            ])
        
        if unexpected_sgid:
            remediation_parts.extend([
                "",
                "Unexpected SGID files:",
            ])
            for f in unexpected_sgid:
                remediation_parts.append(f"  - {f['path']} ({f['mode_string']})")
            remediation_parts.extend([
                "",
                "To remove SGID bit:",
                "  sudo chmod g-s <filepath>",
            ])
        
        remediation_parts.extend([
            "",
            "If these files legitimately need SUID/SGID, add them to the whitelist.",
            "Otherwise, remove the special permissions to prevent privilege escalation.",
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
