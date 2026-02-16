"""
CIS Audit Check: System Accounts Secured (5.4.2)

Ensures system accounts are secured by verifying they are not
login-enabled and have non-interactive shells.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class SystemAccountsSecuredCheck(BaseCheck):
    """Check that system accounts are properly secured."""

    id = "user_system_accounts"
    name = "System Accounts Secured"
    description = (
        "Verifies that system accounts (non-login accounts) are secured "
        "with no shell or a non-login shell"
    )
    severity = Severity.HIGH
    requires_root = True

    PASSWD_FILE = "/etc/passwd"
    SHADOW_FILE = "/etc/shadow"
    
    # System accounts (UID < 1000, excluding root and special accounts)
    SYSTEM_UID_MAX = 999
    
    # Allowed non-login shells
    NON_LOGIN_SHELLS = [
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "/dev/null",
        "/bin/sync",
        "/sbin/shutdown",
        "/sbin/halt",
    ]
    
    # Accounts that are allowed to have login shells (even with low UID)
    ALLOWED_LOGIN_ACCOUNTS = [
        "root",
    ]

    def _get_system_accounts(self) -> dict:
        """Get system accounts from /etc/passwd.

        Returns:
            Dictionary with account information
        """
        result = {
            "file_read": False,
            "system_accounts": [],
            "accounts_with_shell": [],
            "accounts_with_password": [],
        }

        if not os.path.exists(self.PASSWD_FILE):
            return result

        try:
            with open(self.PASSWD_FILE, "r") as f:
                result["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) < 7:
                        continue

                    username = parts[0]
                    uid = int(parts[2]) if parts[2].isdigit() else None
                    gid = int(parts[3]) if parts[3].isdigit() else None
                    home = parts[5]
                    shell = parts[6]

                    # Skip if not a system account
                    if uid is None or uid > self.SYSTEM_UID_MAX:
                        continue

                    # Skip allowed login accounts
                    if username in self.ALLOWED_LOGIN_ACCOUNTS:
                        continue

                    account_info = {
                        "username": username,
                        "uid": uid,
                        "gid": gid,
                        "home": home,
                        "shell": shell,
                    }
                    result["system_accounts"].append(account_info)

                    # Check if account has a login shell
                    if shell and shell not in self.NON_LOGIN_SHELLS:
                        result["accounts_with_shell"].append(account_info)

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def _check_shadow_passwords(self, system_accounts: list) -> dict:
        """Check if system accounts have passwords in shadow.

        Args:
            system_accounts: List of system account dicts

        Returns:
            Dictionary with findings
        """
        result = {
            "file_read": False,
            "accounts_with_password": [],
            "accounts_locked": [],
        }

        if not os.path.exists(self.SHADOW_FILE):
            return result

        # Build set of system account names
        system_names = {acc["username"] for acc in system_accounts}

        try:
            with open(self.SHADOW_FILE, "r") as f:
                result["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) < 2:
                        continue

                    username = parts[0]
                    password = parts[1]

                    # Skip if not a system account
                    if username not in system_names:
                        continue

                    # Check password status
                    if password and password not in ("*", "!", "!!", "x", ""):
                        # Has a password hash
                        result["accounts_with_password"].append({
                            "username": username,
                            "password_type": "set",
                        })
                    elif password and (password.startswith("!") or password.startswith("*")):
                        # Locked account
                        result["accounts_locked"].append(username)

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the system accounts secured check.

        Returns:
            CheckResult with the outcome of the check
        """
        passwd_info = self._get_system_accounts()

        # Check for errors
        if "error" in passwd_info:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Error reading {self.PASSWD_FILE}: {passwd_info['error']}",
                remediation="Check file permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=passwd_info,
            )

        if not passwd_info["file_read"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cannot read {self.PASSWD_FILE}",
                remediation="Ensure the file exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
                details=passwd_info,
            )

        # Check shadow for password status
        shadow_info = self._check_shadow_passwords(passwd_info["system_accounts"])

        details = {
            "passwd": passwd_info,
            "shadow": shadow_info,
        }

        issues = []
        recommendations = []

        # Check for system accounts with login shells
        if passwd_info["accounts_with_shell"]:
            accounts_list = ", ".join([
                f"{acc['username']}({acc['shell']})"
                for acc in passwd_info["accounts_with_shell"][:5]
            ])
            if len(passwd_info["accounts_with_shell"]) > 5:
                accounts_list += "..."
            issues.append(
                f"{len(passwd_info['accounts_with_shell'])} system account(s) have login shells: {accounts_list}"
            )
            recommendations.append(
                "Change shell to /sbin/nologin for system accounts:\n"
                "usermod -s /sbin/nologin <username>"
            )

        # Check for system accounts with passwords
        if shadow_info["accounts_with_password"]:
            accounts_list = ", ".join([
                acc["username"]
                for acc in shadow_info["accounts_with_password"][:5]
            ])
            if len(shadow_info["accounts_with_password"]) > 5:
                accounts_list += "..."
            issues.append(
                f"{len(shadow_info['accounts_with_password'])} system account(s) have passwords: {accounts_list}"
            )
            recommendations.append(
                "Lock system accounts:\n"
                "passwd -l <username>"
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"System accounts security issues: {'; '.join(issues[:2])}",
                remediation=(
                    "Secure system accounts:\n\n"
                    + "\n\n".join(recommendations)
                    + "\n\nTo secure all system accounts at once:\n"
                    "awk -F: '$3 < 1000 && $1 != \"root\" {print $1}' /etc/passwd | "
                    "while read user; do\n"
                    "  usermod -s /sbin/nologin \"$user\" 2>/dev/null\n"
                    "  passwd -l \"$user\" 2>/dev/null\n"
                    "done"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(passwd_info['system_accounts'])} system accounts are properly secured",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
