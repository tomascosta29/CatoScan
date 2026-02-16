"""
CIS Audit Check: Default User umask (5.4.4)

Ensures the default user umask is set to 027 or more restrictive
(077) in /etc/profile, /etc/bashrc, /etc/bash.bashrc, and
/etc/login.defs.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class UserUmaskCheck(BaseCheck):
    """Check for default user umask configuration."""

    id = "user_umask"
    name = "Default User umask"
    description = (
        "Verifies that the default user umask is set to 027 or more restrictive "
        "in system-wide configuration files"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Files to check (in order of priority)
    UMASK_FILES = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash.bashrc",
        "/etc/login.defs",
        "/etc/profile.d/*.sh",
    ]
    
    # CIS recommended umask values (027 is minimum, 077 is ideal)
    MIN_UMASK = 0o027  # 027
    IDEAL_UMASK = 0o077  # 077

    def _extract_umask_from_file(self, filepath: str) -> tuple[int | None, str | None]:
        """Extract umask value from a file.

        Args:
            filepath: Path to the file

        Returns:
            Tuple of (umask_value, line_found) or (None, None)
        """
        path = Path(filepath)
        if not path.exists():
            return None, None

        try:
            with open(path, "r") as f:
                for line in f:
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith("#"):
                        continue

                    # Look for umask setting
                    # Match patterns like: umask 027, umask 0077, UMASK 027
                    match = re.search(r"(?:^|\s)umask\s+([0-7]{3,4})\b", line_stripped, re.IGNORECASE)
                    if match:
                        umask_str = match.group(1)
                        # Handle both 027 and 0027 formats
                        if len(umask_str) == 4:
                            umask_str = umask_str[1:]  # Remove leading 0
                        try:
                            return int(umask_str, 8), line_stripped
                        except ValueError:
                            continue

        except (IOError, OSError):
            pass

        return None, None

    def _check_all_umask_configs(self) -> dict:
        """Check all configuration files for umask settings.

        Returns:
            Dictionary with findings
        """
        result = {
            "files_checked": [],
            "umask_settings": [],
            "most_permissive": None,
            "most_restrictive": None,
        }

        for pattern in self.UMASK_FILES:
            if "*" in pattern:
                # Handle glob patterns
                import glob
                files = glob.glob(pattern)
                for filepath in sorted(files):
                    umask, line = self._extract_umask_from_file(filepath)
                    result["files_checked"].append(filepath)
                    if umask is not None:
                        result["umask_settings"].append({
                            "file": filepath,
                            "umask": oct(umask)[2:].zfill(3),
                            "umask_oct": umask,
                            "line": line,
                        })
                        if result["most_permissive"] is None or umask < result["most_permissive"]:
                            result["most_permissive"] = umask
                        if result["most_restrictive"] is None or umask > result["most_restrictive"]:
                            result["most_restrictive"] = umask
            else:
                umask, line = self._extract_umask_from_file(pattern)
                result["files_checked"].append(pattern)
                if umask is not None:
                    result["umask_settings"].append({
                        "file": pattern,
                        "umask": oct(umask)[2:].zfill(3),
                        "umask_oct": umask,
                        "line": line,
                    })
                    if result["most_permissive"] is None or umask < result["most_permissive"]:
                        result["most_permissive"] = umask
                    if result["most_restrictive"] is None or umask > result["most_restrictive"]:
                        result["most_restrictive"] = umask

        return result

    def _check_useradd_umask(self) -> dict:
        """Check /etc/login.defs for UMASK setting used by useradd.

        Returns:
            Dictionary with configuration
        """
        result = {
            "file_read": False,
            "umask": None,
        }

        login_defs = "/etc/login.defs"
        if not os.path.exists(login_defs):
            return result

        try:
            with open(login_defs, "r") as f:
                result["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Check for UMASK (uppercase in login.defs)
                    match = re.match(r"^UMASK\s+(\d{3,4})", line)
                    if match:
                        umask_str = match.group(1)
                        if len(umask_str) == 4:
                            umask_str = umask_str[1:]
                        try:
                            result["umask"] = int(umask_str, 8)
                        except ValueError:
                            continue

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the default umask check.

        Returns:
            CheckResult with the outcome of the check
        """
        umask_configs = self._check_all_umask_configs()
        useradd_umask = self._check_useradd_umask()

        details = {
            "umask_configs": umask_configs,
            "useradd_umask": useradd_umask,
        }

        # Check if any umask is configured
        if not umask_configs["umask_settings"] and useradd_umask["umask"] is None:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No umask configuration found in system-wide files",
                remediation=(
                    "Set a restrictive umask in /etc/profile or /etc/bashrc:\n\n"
                    "Add the following line to /etc/profile:\n"
                    "umask 027\n\n"
                    "Or for more restrictive (recommended):\n"
                    "umask 077\n\n"
                    "Also set in /etc/login.defs for new users:\n"
                    "UMASK 027"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        recommendations = []

        # Check the most permissive umask found
        most_permissive = umask_configs["most_permissive"]
        if most_permissive is not None and most_permissive > self.MIN_UMASK:
            # Note: higher octal value = more restrictive
            # So if most_permissive > MIN_UMASK, it's actually more permissive
            # Wait, that's wrong. Let me think again:
            # 022 = more permissive (owner: rwx, group: rx, other: rx)
            # 027 = less permissive (owner: rwx, group: rx, other: none)
            # 077 = most restrictive (owner: rwx, group: none, other: none)
            # So 022 < 027 < 077 numerically
            # We want umask >= 027 (numerically)
            pass

        # Re-evaluate: umask is applied as a mask
        # 022 = 000 010 010 = rw-r--r-- for files
        # 027 = 000 010 111 = rw-r----- for files
        # 077 = 000 111 111 = rw------- for files
        # So higher umask = more restrictive
        # We want umask >= 027

        # Check shell umask configs
        if most_permissive is not None:
            if most_permissive < self.MIN_UMASK:
                # Less than 027 = too permissive
                issues.append(
                    f"Most permissive umask is {oct(most_permissive)[2:].zfill(3)} "
                    f"(recommended: 027 or more restrictive)"
                )
                recommendations.append(
                    "Set umask 027 (or 077) in /etc/profile and /etc/bashrc"
                )

        # Check useradd umask
        if useradd_umask["umask"] is not None:
            if useradd_umask["umask"] < self.MIN_UMASK:
                issues.append(
                    f"login.defs UMASK is {oct(useradd_umask['umask'])[2:].zfill(3)} "
                    f"(recommended: 027 or more restrictive)"
                )
                recommendations.append(
                    "Set UMASK 027 in /etc/login.defs"
                )
        else:
            issues.append("UMASK is not set in /etc/login.defs")
            recommendations.append("Set UMASK 027 in /etc/login.defs")

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Umask configuration issues: {'; '.join(issues[:2])}",
                remediation=(
                    "Configure a restrictive umask:\n\n"
                    + "\n".join(recommendations)
                    + "\n\nExample /etc/profile addition:\n"
                    "if [ \"$(id - gn)\" = \"$(id - un)\" -a $EUID -gt 99 ]; then\n"
                    "  umask 002\n"
                    "else\n"
                    "  umask 027\n"
                    "fi\n\n"
                    "Or simply add to /etc/profile and /etc/bashrc:\n"
                    "umask 027"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Determine the effective umask to report
        effective_umask = most_permissive if most_permissive is not None else useradd_umask.get("umask")
        umask_str = oct(effective_umask)[2:].zfill(3) if effective_umask else "unknown"

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Default umask is properly configured ({umask_str})",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
