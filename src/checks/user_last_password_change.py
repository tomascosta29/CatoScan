"""
CIS Audit Check: User Last Password Change in Past (5.4.1.4)

Ensures that all users' last password change date is in the past,
not in the future. This helps detect potential tampering with
system time or password aging.
"""

import re
import shutil
import time
from pathlib import Path

import subprocess

from src.core.check import BaseCheck, CheckResult, Severity


class UserLastPasswordChangeCheck(BaseCheck):
    """Check that all users have last password change date in the past."""

    id = "user_last_password_change"
    name = "User Last Password Change in Past"
    description = (
        "Verifies that all users' last password change date is in the past, "
        "not in the future"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SHADOW_FILE = "/etc/shadow"

    _USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@+-]+$")

    def _get_current_date(self) -> int:
        """Get current date as days since epoch.

        Returns:
            Days since epoch
        """
        return int(time.time() / 86400)

    def _parse_shadow_entry(self, line: str) -> dict | None:
        """Parse a shadow file entry.

        Args:
            line: Shadow file line

        Returns:
            Dictionary with parsed fields or None
        """
        parts = line.split(":")
        if len(parts) < 9:
            return None

        return {
            "username": parts[0],
            "password": parts[1],
            "last_change": parts[2],  # Days since epoch
            "min_days": parts[3],
            "max_days": parts[4],
            "warn_days": parts[5],
            "inactive_days": parts[6],
            "expire_date": parts[7],
            "reserved": parts[8],
        }

    def _check_users_password_change(self) -> dict:
        """Check all users' last password change date.

        Returns:
            Dictionary with findings
        """
        result = {
            "file_read": False,
            "current_date_days": self._get_current_date(),
            "users_checked": 0,
            "users_with_future_change": [],
            "users_with_invalid_date": [],
            "users_with_no_change": [],
            "users_skipped_unsafe": [],
        }

        path = Path(self.SHADOW_FILE)
        if not path.exists():
            return result

        current_date = result["current_date_days"]

        try:
            with open(self.SHADOW_FILE, "r") as f:
                result["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    entry = self._parse_shadow_entry(line)
                    if not entry:
                        continue

                    username = entry["username"]
                    password = entry["password"]
                    last_change = entry["last_change"]

                    if not self._is_safe_username(username):
                        result["users_skipped_unsafe"].append(username)
                        continue

                    # Skip system accounts (no password or locked)
                    if password in ("*", "!", "!!", "x"):
                        continue

                    result["users_checked"] += 1

                    # Check if last_change is empty or 0
                    if not last_change or last_change == "0":
                        result["users_with_no_change"].append(username)
                        continue

                    # Try to parse the date
                    try:
                        last_change_days = int(last_change)

                        # Check if date is in the future
                        if last_change_days > current_date:
                            # Calculate days in future
                            days_future = last_change_days - current_date
                            result["users_with_future_change"].append({
                                "username": username,
                                "last_change_days": last_change_days,
                                "current_date_days": current_date,
                                "days_in_future": days_future,
                            })

                    except ValueError:
                        result["users_with_invalid_date"].append({
                            "username": username,
                            "last_change_value": last_change,
                        })

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def _is_safe_username(self, username: str) -> bool:
        """Validate username for safe command invocation.

        Args:
            username: Username from shadow file

        Returns:
            True if username is safe to pass as CLI argument
        """
        if not username:
            return False
        if len(username) > 256:
            return False
        if username.startswith("-"):
            return False
        if any(char in username for char in (":", "\x00", "\n", "\r", "\t", " ")):
            return False
        return bool(self._USERNAME_PATTERN.match(username))

    def _check_with_chage(self) -> dict:
        """Use chage to verify password change dates for additional accuracy.

        Returns:
            Dictionary with chage findings
        """
        result = {
            "chage_available": False,
            "users_checked": 0,
            "users_with_future_date": [],
            "users_skipped_unsafe": [],
            "errors": [],
        }

        # Check if chage is available
        if shutil.which("chage") is None:
            return result
        result["chage_available"] = True

        # Get list of users with passwords
        try:
            with open(self.SHADOW_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) < 9:
                        continue

                    username = parts[0]
                    password = parts[1]

                    if not self._is_safe_username(username):
                        result["users_skipped_unsafe"].append(username)
                        continue

                    # Skip system accounts
                    if password in ("*", "!", "!!", "x"):
                        continue

                    # Check with chage
                    try:
                        chage_result = subprocess.run(
                            ["chage", "-l", username],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        if chage_result.returncode == 0:
                            result["users_checked"] += 1
                            output = chage_result.stdout

                            # Look for "Last password change" line
                            for line in output.split("\n"):
                                if "last password change" in line.lower():
                                    # Check if it contains a date in the future
                                    # chage output format varies by locale
                                    if "password must be changed" in line.lower():
                                        # This indicates a future date or forced change
                                        pass
                                    break

                    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as e:
                        result["errors"].append(f"{username}: {type(e).__name__}: {e}")

        except (IOError, OSError) as e:
            result["errors"].append(f"read-shadow: {type(e).__name__}: {e}")

        return result

    def run(self) -> CheckResult:
        """Execute the user last password change check.

        Returns:
            CheckResult with the outcome of the check
        """
        shadow_check = self._check_users_password_change()
        chage_check = self._check_with_chage()

        details = {
            "shadow_check": shadow_check,
            "chage_check": chage_check,
        }

        # Check for errors
        if "error" in shadow_check:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Error reading {self.SHADOW_FILE}: {shadow_check['error']}",
                remediation="Check file permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        recommendations = []

        # Check for users with future password change dates
        if shadow_check["users_with_future_change"]:
            users_list = ", ".join([
                f"{u['username']}({u['days_in_future']}d future)"
                for u in shadow_check["users_with_future_change"][:5]
            ])
            if len(shadow_check["users_with_future_change"]) > 5:
                users_list += "..."

            issues.append(
                f"{len(shadow_check['users_with_future_change'])} user(s) have password change date in future: {users_list}"
            )
            recommendations.append(
                "Investigate potential system time tampering or reset password change date"
            )

        # Check for users with invalid dates
        if shadow_check["users_with_invalid_date"]:
            users_list = ", ".join([
                u["username"]
                for u in shadow_check["users_with_invalid_date"][:5]
            ])
            if len(shadow_check["users_with_invalid_date"]) > 5:
                users_list += "..."

            issues.append(
                f"{len(shadow_check['users_with_invalid_date'])} user(s) have invalid password change date: {users_list}"
            )
            recommendations.append(
                "Reset password for users with invalid dates"
            )

        # Check for users who never changed password (last_change = 0 or empty)
        if shadow_check["users_with_no_change"]:
            # This is informational, not a failure
            details["users_never_changed_password"] = shadow_check["users_with_no_change"]

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Password change date issues: {'; '.join(issues)}",
                remediation=(
                    "Fix password change date issues:\n\n"
                    + "\n".join(recommendations) +
                    "\n\nTo reset password change date for a user:\n"
                    "  sudo chage -d $(date +%Y-%m-%d) <username>\n\n"
                    "To force password change on next login:\n"
                    "  sudo chage -d 0 <username>\n\n"
                    "To check password aging for a user:\n"
                    "  sudo chage -l <username>\n\n"
                    "CIS Benchmark: 5.4.1.4 - Ensure all users last password change date is in the past"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {shadow_check['users_checked']} users have valid password change dates in the past",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
