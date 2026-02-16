"""
CIS Audit Check: Home Directory Permissions (6.2.11)

Ensures users' home directories have appropriate permissions.
Home directories should not be writable by group or others.
"""

import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class HomePermissionsCheck(BaseCheck):
    """Check home directory permissions."""

    id = "user_home_perms"
    name = "Home Directory Permissions"
    description = (
        "Verifies that users' home directories are not writable "
        "by group or others"
    )
    severity = Severity.MEDIUM
    requires_root = True

    PASSWD_PATH = "/etc/passwd"

    # Maximum allowed permissions for home directories
    # (rwx------ or more restrictive)
    MAX_ALLOWED_MODE = 0o755

    # System users to exclude
    EXCLUDE_USERS = [
        "root",
        "halt",
        "sync",
        "shutdown",
        "nfsnobody",
    ]

    def _parse_passwd(self) -> list[dict]:
        """Parse /etc/passwd and return user entries with homes.

        Returns:
            List of passwd entries
        """
        entries = []
        path = Path(self.PASSWD_PATH)

        if not path.exists():
            return entries

        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) >= 6:
                        username = parts[0]
                        uid = parts[2]
                        home = parts[5]

                        # Skip excluded users
                        if username in self.EXCLUDE_USERS:
                            continue

                        # Skip users with no home or system homes
                        if not home or home in ("/", "/nonexistent", "/var/empty"):
                            continue

                        try:
                            uid_num = int(uid)
                            entries.append({
                                "username": username,
                                "uid": uid_num,
                                "home": home,
                            })
                        except ValueError:
                            pass
        except (IOError, OSError):
            pass

        return entries

    def _check_home_permissions(self, home_path: Path) -> dict:
        """Check permissions of a home directory.

        Args:
            home_path: Path to the home directory

        Returns:
            Dictionary with check results
        """
        result = {
            "exists": False,
            "is_dir": False,
            "mode_ok": False,
            "owner_match": False,
            "actual_mode": None,
            "actual_uid": None,
            "mode_string": None,
        }

        if not home_path.exists():
            return result

        result["exists"] = True

        if not home_path.is_dir():
            return result

        result["is_dir"] = True

        try:
            st = home_path.stat()
            mode = stat.S_IMODE(st.st_mode)

            result["actual_mode"] = mode
            result["actual_uid"] = st.st_uid
            result["mode_string"] = stat.filemode(st.st_mode)

            # Check if mode is acceptable (no group/other write)
            # Allow 755, 750, 700, etc. but not 777, 775, etc.
            result["mode_ok"] = (mode & 0o022) == 0

        except (IOError, OSError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the home directory permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        entries = self._parse_passwd()

        if not entries:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.PASSWD_PATH}",
                remediation=f"Verify {self.PASSWD_PATH} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
            )

        # Check permissions for each home directory
        bad_permissions = []
        for entry in entries:
            home_path = Path(entry["home"])
            perm_check = self._check_home_permissions(home_path)

            if perm_check["exists"] and perm_check["is_dir"] and not perm_check["mode_ok"]:
                bad_permissions.append({
                    "username": entry["username"],
                    "home": entry["home"],
                    "mode": perm_check["mode_string"],
                    "mode_octal": oct(perm_check["actual_mode"]) if perm_check["actual_mode"] else None,
                })

        if bad_permissions:
            users = [p["username"] for p in bad_permissions[:10]]
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(bad_permissions)} home directory(s) with insecure permissions: "
                    f"{', '.join(users)}"
                    f"{'...' if len(bad_permissions) > 10 else ''}"
                ),
                remediation=(
                    "Fix home directory permissions:\n\n"
                    "Remove group and other write permissions:\n"
                    "  sudo chmod go-w /home/<username>\n\n"
                    "Or set more restrictive permissions:\n"
                    "  sudo chmod 700 /home/<username>\n\n"
                    "Verify ownership:\n"
                    "  sudo chown <username>:<username> /home/<username>\n\n"
                    "CIS Benchmark: 6.2.11 - Ensure users' home directories permissions are 750 or more restrictive"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"bad_permissions": bad_permissions},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} home directories have secure permissions",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_users": len(entries)},
        )
