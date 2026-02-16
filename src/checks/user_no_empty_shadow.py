"""
CIS Audit Check: No Empty Shadow Passwords (6.2.2)

Ensures no accounts in /etc/shadow have empty password fields.
Empty password fields allow passwordless login.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class NoEmptyShadowPasswordsCheck(BaseCheck):
    """Check that no shadow entries have empty passwords."""

    id = "user_no_empty_shadow"
    name = "No Empty Shadow Passwords"
    description = (
        "Verifies that no accounts in /etc/shadow have empty password fields "
        "which would allow passwordless login"
    )
    severity = Severity.HIGH
    requires_root = True

    SHADOW_PATH = "/etc/shadow"

    def _parse_shadow(self) -> list[dict]:
        """Parse /etc/shadow and return entries.

        Returns:
            List of shadow entries with username and password field
        """
        entries = []
        path = Path(self.SHADOW_PATH)

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
        """Execute the empty shadow password check.

        Returns:
            CheckResult with the outcome of the check
        """
        entries = self._parse_shadow()

        if not entries:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.SHADOW_PATH}",
                remediation=f"Verify {self.SHADOW_PATH} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
            )

        # Find entries with empty passwords
        # Empty field ("") means no password required
        empty_passwords = []
        for entry in entries:
            passwd = entry["password"]
            # Empty string means passwordless login allowed
            if passwd == "":
                empty_passwords.append(entry["username"])

        if empty_passwords:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(empty_passwords)} account(s) with empty passwords: "
                    f"{', '.join(empty_passwords[:10])}"
                    f"{'...' if len(empty_passwords) > 10 else ''}"
                ),
                remediation=(
                    "Lock accounts with empty passwords or set passwords:\n"
                    "  sudo passwd -l <username>  # Lock the account\n"
                    "  OR\n"
                    "  sudo passwd <username>     # Set a password\n\n"
                    "CIS Benchmark: 6.2.2 - Ensure no legacy '+' entries exist in /etc/shadow"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"empty_password_accounts": empty_passwords},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="No accounts have empty passwords in /etc/shadow",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_accounts": len(entries)},
        )
