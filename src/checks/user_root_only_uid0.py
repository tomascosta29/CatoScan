"""
CIS Audit Check: Root Only UID 0 (6.2.9)

Ensures that only the root account has UID 0 (superuser privileges).
Multiple accounts with UID 0 represent a serious security risk.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class RootOnlyUID0Check(BaseCheck):
    """Check that only root has UID 0."""

    id = "user_root_only_uid0"
    name = "Root Only UID 0"
    description = (
        "Verifies that only the root account has UID 0 "
        "(superuser privileges)"
    )
    severity = Severity.HIGH
    requires_root = True

    PASSWD_PATH = "/etc/passwd"

    def _parse_passwd(self) -> list[dict]:
        """Parse /etc/passwd and return entries with UID 0.

        Returns:
            List of passwd entries with UID 0
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
                            if uid == 0:
                                entries.append({
                                    "username": parts[0],
                                    "uid": uid,
                                    "gid": parts[3] if len(parts) > 3 else "",
                                    "home": parts[5] if len(parts) > 5 else "",
                                    "shell": parts[6] if len(parts) > 6 else "",
                                })
                        except ValueError:
                            pass
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the root-only UID 0 check.

        Returns:
            CheckResult with the outcome of the check
        """
        uid0_entries = self._parse_passwd()

        if not uid0_entries:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.PASSWD_PATH} or no UID 0 entries found",
                remediation=f"Verify {self.PASSWD_PATH} exists and contains a root entry",
                severity=self.severity,
                requires_root=self.requires_root,
            )

        # Check if only root has UID 0
        non_root_uid0 = [e for e in uid0_entries if e["username"] != "root"]

        if non_root_uid0:
            usernames = [e["username"] for e in non_root_uid0]
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"CRITICAL: Found {len(non_root_uid0)} non-root account(s) with UID 0: "
                    f"{', '.join(usernames)}"
                ),
                remediation=(
                    "CRITICAL SECURITY ISSUE: Multiple accounts have superuser privileges.\n\n"
                    "Remove or reassign UID 0 from non-root accounts:\n"
                    "  sudo usermod -u <new_uid> <username>\n\n"
                    "Or delete the account if not needed:\n"
                    "  sudo userdel <username>\n\n"
                    "Only the 'root' account should have UID 0.\n\n"
                    "CIS Benchmark: 6.2.9 - Ensure root is the only UID 0 account"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "non_root_uid0_accounts": non_root_uid0,
                    "all_uid0_accounts": uid0_entries,
                },
            )

        # Verify root exists with UID 0
        root_entry = next((e for e in uid0_entries if e["username"] == "root"), None)

        if not root_entry:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No root account with UID 0 found",
                remediation=(
                    "CRITICAL: The root account is missing or does not have UID 0.\n"
                    "This may indicate system compromise or corruption.\n"
                    "Restore /etc/passwd from backup or recovery mode."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Only the root account has UID 0 (superuser privileges)",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"root_entry": root_entry},
        )
