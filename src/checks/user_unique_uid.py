"""
CIS Audit Check: Unique UIDs (6.2.4)

Ensures all users in /etc/passwd have unique UIDs.
Duplicate UIDs can lead to security issues and privilege confusion.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class UniqueUIDCheck(BaseCheck):
    """Check that all UIDs are unique."""

    id = "user_unique_uid"
    name = "Unique UIDs"
    description = (
        "Verifies that all user accounts in /etc/passwd have unique UIDs"
    )
    severity = Severity.MEDIUM
    requires_root = True

    PASSWD_PATH = "/etc/passwd"

    def _parse_passwd(self) -> list[dict]:
        """Parse /etc/passwd and return entries.

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
                    if len(parts) >= 3:
                        try:
                            uid = int(parts[2])
                            entries.append({
                                "username": parts[0],
                                "uid": uid,
                            })
                        except ValueError:
                            pass
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the unique UID check.

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

        # Find duplicate UIDs
        uid_to_users: dict[int, list[str]] = {}
        for entry in entries:
            uid = entry["uid"]
            if uid not in uid_to_users:
                uid_to_users[uid] = []
            uid_to_users[uid].append(entry["username"])

        duplicates = {uid: users for uid, users in uid_to_users.items() if len(users) > 1}

        if duplicates:
            dup_str = ", ".join(
                f"UID {uid}: {', '.join(users)}"
                for uid, users in list(duplicates.items())[:5]
            )
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Found duplicate UIDs: {dup_str}",
                remediation=(
                    "Assign unique UIDs to each user account:\n"
                    "  sudo usermod -u <new_uid> <username>\n\n"
                    "Note: Changing UIDs may require updating file ownership.\n\n"
                    "CIS Benchmark: 6.2.4 - Ensure no duplicate UIDs exist"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"duplicates": duplicates},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} user accounts have unique UIDs",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_users": len(entries)},
        )
