"""
CIS Audit Check: Shadowed Passwords (6.2.1)

Ensures all passwords in /etc/passwd are shadowed (stored in /etc/shadow).
No password hashes should exist in /etc/passwd.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class ShadowedPasswordsCheck(BaseCheck):
    """Check that all passwords are shadowed."""

    id = "user_shadowed_passwords"
    name = "Shadowed Passwords"
    description = (
        "Verifies that all passwords are stored in /etc/shadow "
        "and no password hashes exist in /etc/passwd"
    )
    severity = Severity.MEDIUM
    requires_root = True

    PASSWD_PATH = "/etc/passwd"

    def _parse_passwd(self) -> list[dict]:
        """Parse /etc/passwd and return entries.

        Returns:
            List of passwd entries with username and password field
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
                    if len(parts) >= 2:
                        entries.append({
                            "username": parts[0],
                            "password": parts[1],
                        })
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the shadowed passwords check.

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

        # Find entries with non-shadowed passwords
        # 'x' means shadowed, '*' or '!' typically means locked/no password
        # Anything else (especially starting with $ or having length > 2) is likely a hash
        non_shadowed = []
        for entry in entries:
            passwd = entry["password"]
            # Valid shadowed indicators: 'x', '*', '!', ''
            if passwd not in ("x", "*", "!", ""):
                # Check if it looks like a password hash
                if len(passwd) > 2 or passwd.startswith(("$", "_")):
                    non_shadowed.append(entry["username"])

        if non_shadowed:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(non_shadowed)} account(s) with non-shadowed passwords: "
                    f"{', '.join(non_shadowed[:10])}"
                    f"{'...' if len(non_shadowed) > 10 else ''}"
                ),
                remediation=(
                    "Convert password hashes from /etc/passwd to /etc/shadow:\n"
                    "  sudo pwconv\n\n"
                    "This will move all password hashes to /etc/shadow.\n\n"
                    "CIS Benchmark: 6.2.1 - Ensure password fields are not empty"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"non_shadowed_accounts": non_shadowed},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="All passwords are properly shadowed in /etc/shadow",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_accounts": len(entries)},
        )
