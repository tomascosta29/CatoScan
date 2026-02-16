"""
CIS Audit Check: Unique Usernames (6.2.6)

Ensures all entries in /etc/passwd have unique usernames.
Duplicate usernames can cause authentication and authorization issues.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class UniqueUsernameCheck(BaseCheck):
    """Check that all usernames are unique."""

    id = "user_unique_name"
    name = "Unique Usernames"
    description = (
        "Verifies that all entries in /etc/passwd have unique usernames"
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
                    if len(parts) >= 1:
                        entries.append({
                            "username": parts[0],
                            "line": line,
                        })
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the unique username check.

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

        # Find duplicate usernames
        username_counts: dict[str, int] = {}
        for entry in entries:
            username = entry["username"]
            username_counts[username] = username_counts.get(username, 0) + 1

        duplicates = {name: count for name, count in username_counts.items() if count > 1}

        if duplicates:
            dup_str = ", ".join(f"{name} ({count} times)" for name, count in list(duplicates.items())[:5])
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Found duplicate usernames: {dup_str}",
                remediation=(
                    "Remove or rename duplicate user entries in /etc/passwd:\n"
                    "  sudo usermod -l <new_name> <old_name>\n"
                    "  OR manually edit /etc/passwd (with extreme caution)\n\n"
                    "CIS Benchmark: 6.2.6 - Ensure no duplicate user names exist"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"duplicates": duplicates},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} entries have unique usernames",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_users": len(entries)},
        )
