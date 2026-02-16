"""
CIS Audit Check: Empty Password Accounts

Checks for user accounts with empty passwords that can be used
to login without authentication.
"""

import os
import re
import pwd

from src.core.check import BaseCheck, CheckResult, Severity


class EmptyPasswordCheck(BaseCheck):
    """Check for accounts with empty passwords."""

    id = "auth_empty_passwords"
    name = "Empty Password Accounts"
    description = (
        "Identifies user accounts that have empty passwords "
        "and can be used to login without authentication"
    )
    severity = Severity.CRITICAL
    requires_root = True

    SHADOW_FILE = "/etc/shadow"

    # System accounts that typically don't have passwords (and shouldn't login)
    SYSTEM_ACCOUNTS = {
        "root", "bin", "daemon", "adm", "lp", "sync", "shutdown", "halt",
        "mail", "operator", "games", "ftp", "nobody", "dbus", "systemd-coredump",
        "systemd-network", "systemd-resolve", "tss", "polkitd", "unbound",
        "sssd", "chrony", "setroubleshoot", "pipewire", "geoclue", "rtkit",
        "qemu", "clevis", "cockpit-ws", "sshd", "tcpdump", "avahi", "dnsmasq",
    }

    def _parse_shadow(self) -> tuple[list[dict], dict]:
        """Parse /etc/shadow for accounts with empty passwords.

        Returns:
            Tuple of (empty_password_accounts, details)
        """
        empty_accounts = []
        details = {
            "shadow_readable": False,
            "total_accounts": 0,
            "locked_accounts": 0,
            "empty_password_accounts": 0,
            "errors": [],
        }

        if not os.path.exists(self.SHADOW_FILE):
            details["errors"].append(f"{self.SHADOW_FILE} does not exist")
            return empty_accounts, details

        try:
            with open(self.SHADOW_FILE, "r") as f:
                details["shadow_readable"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    details["total_accounts"] += 1

                    # Parse shadow entry: username:password:lastchg:min:max:warn:inactive:expire:reserved
                    parts = line.split(":")
                    if len(parts) < 2:
                        continue

                    username = parts[0]
                    password_hash = parts[1]

                    # Check for empty password (no hash at all)
                    if password_hash == "":
                        details["empty_password_accounts"] += 1
                        empty_accounts.append({
                            "username": username,
                            "type": "empty",
                            "is_system": username in self.SYSTEM_ACCOUNTS,
                        })
                        continue

                    # Check for locked account (! or * at start)
                    if password_hash.startswith("!") or password_hash.startswith("*"):
                        details["locked_accounts"] += 1
                        continue

                    # Check for nullok equivalent (rare, but some systems use specific patterns)
                    # An empty password field means no password required

        except PermissionError as e:
            details["errors"].append(f"Permission denied reading {self.SHADOW_FILE}: {str(e)}")
        except (IOError, OSError) as e:
            details["errors"].append(f"Error reading {self.SHADOW_FILE}: {str(e)}")

        return empty_accounts, details

    def _get_account_info(self, username: str) -> dict:
        """Get additional information about a user account.

        Args:
            username: The username to look up

        Returns:
            Dictionary with account information
        """
        info = {
            "uid": None,
            "gid": None,
            "home": None,
            "shell": None,
        }

        try:
            user_info = pwd.getpwnam(username)
            info["uid"] = user_info.pw_uid
            info["gid"] = user_info.pw_gid
            info["home"] = user_info.pw_dir
            info["shell"] = user_info.pw_shell
            info["has_login_shell"] = info["shell"] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin")
        except KeyError:
            info["error"] = "User not found in /etc/passwd"

        return info

    def run(self) -> CheckResult:
        """Execute the empty password check.

        Returns:
            CheckResult with the outcome of the check
        """
        empty_accounts, details = self._parse_shadow()

        # Check for errors
        if details["errors"] and not details["shadow_readable"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cannot read shadow file: {'; '.join(details['errors'])}",
                remediation="Run the check with root privileges to read /etc/shadow",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Get additional info for empty password accounts
        accounts_with_info = []
        login_capable_accounts = []

        for account in empty_accounts:
            info = self._get_account_info(account["username"])
            account_info = {**account, **info}
            accounts_with_info.append(account_info)

            # Check if account can actually login
            if info.get("has_login_shell"):
                login_capable_accounts.append(account_info)

        details["accounts"] = accounts_with_info
        details["login_capable_accounts"] = login_capable_accounts

        if empty_accounts:
            # Critical: accounts with empty passwords exist
            account_list = ", ".join([a["username"] for a in empty_accounts])

            if login_capable_accounts:
                login_list = ", ".join([a["username"] for a in login_capable_accounts])
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message=(
                        f"CRITICAL: {len(login_capable_accounts)} account(s) with empty passwords "
                        f"can login without authentication: {login_list}"
                    ),
                    remediation=(
                        "Immediately lock or set passwords for these accounts:\n"
                        f"Affected accounts: {login_list}\n\n"
                        "To lock an account:\n"
                        "  passwd -l <username>\n\n"
                        "To set a password:\n"
                        "  passwd <username>\n\n"
                        "To verify no empty passwords exist:\n"
                        "  awk -F: '($2 == \"\") {print}' /etc/shadow"
                    ),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=details,
                )
            else:
                # Empty passwords but no login shell (less critical but still bad)
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message=(
                        f"Found {len(empty_accounts)} account(s) with empty passwords: {account_list}. "
                        "These accounts currently cannot login (no valid shell), but this is still a security risk."
                    ),
                    remediation=(
                        f"Lock these accounts to prevent potential future exploitation: {account_list}\n\n"
                        "To lock an account:\n"
                        "  passwd -l <username>\n\n"
                        "Or set a strong password:\n"
                        "  passwd <username>"
                    ),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=details,
                )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"No accounts with empty passwords found (checked {details['total_accounts']} accounts)",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
