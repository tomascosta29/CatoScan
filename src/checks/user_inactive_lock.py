"""
CIS Audit Check: Inactive Password Lock (5.4.1.4)

Ensures inactive user accounts are locked after 30 days or less
by checking INACTIVE setting in /etc/default/useradd and
user-specific settings in /etc/shadow.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class InactivePasswordLockCheck(BaseCheck):
    """Check for inactive password lock configuration."""

    id = "user_inactive_lock"
    name = "Inactive Password Lock"
    description = (
        "Verifies that inactive user accounts are locked after 30 days or less "
        "of inactivity"
    )
    severity = Severity.MEDIUM
    requires_root = True

    USERADD_DEFAULTS = "/etc/default/useradd"
    SHADOW_FILE = "/etc/shadow"
    LOGIN_DEFS = "/etc/login.defs"
    MAX_INACTIVE_DAYS = 30

    def _check_useradd_defaults(self) -> dict:
        """Check /etc/default/useradd for INACTIVE setting.

        Returns:
            Dictionary with configuration
        """
        config = {
            "file_read": False,
            "inactive_days": None,
        }

        if not os.path.exists(self.USERADD_DEFAULTS):
            return config

        try:
            with open(self.USERADD_DEFAULTS, "r") as f:
                config["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Check for INACTIVE
                    match = re.match(r"^INACTIVE\s*=\s*(\d+)", line)
                    if match:
                        config["inactive_days"] = int(match.group(1))

        except (IOError, OSError) as e:
            config["error"] = str(e)

        return config

    def _check_shadow_inactive(self) -> dict:
        """Check /etc/shadow for user-specific inactive settings.

        Returns:
            Dictionary with findings
        """
        result = {
            "file_read": False,
            "users_checked": 0,
            "users_with_inactive": [],
            "users_exceeding_limit": [],
            "users_no_inactive": [],
        }

        if not os.path.exists(self.SHADOW_FILE):
            return result

        try:
            with open(self.SHADOW_FILE, "r") as f:
                result["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) < 9:
                        continue

                    username = parts[0]
                    password = parts[1]
                    inactive_field = parts[7]

                    # Skip system accounts (no password or locked)
                    if password in ("*", "!", "!!", "x"):
                        continue

                    result["users_checked"] += 1

                    if inactive_field:
                        try:
                            inactive_days = int(inactive_field)
                            result["users_with_inactive"].append({
                                "username": username,
                                "inactive_days": inactive_days,
                            })

                            if inactive_days > self.MAX_INACTIVE_DAYS or inactive_days < 0:
                                result["users_exceeding_limit"].append({
                                    "username": username,
                                    "inactive_days": inactive_days,
                                })
                        except ValueError:
                            # Non-numeric value, treat as empty
                            result["users_no_inactive"].append(username)
                    else:
                        result["users_no_inactive"].append(username)

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the inactive password lock check.

        Returns:
            CheckResult with the outcome of the check
        """
        useradd_config = self._check_useradd_defaults()
        shadow_config = self._check_shadow_inactive()

        details = {
            "useradd_defaults": useradd_config,
            "shadow_inactive": shadow_config,
        }

        # Check for errors
        if "error" in useradd_config:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Error reading {self.USERADD_DEFAULTS}: {useradd_config['error']}",
                remediation="Check file permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        recommendations = []

        # Check useradd defaults
        if useradd_config["inactive_days"] is None:
            issues.append("INACTIVE is not set in /etc/default/useradd")
            recommendations.append(
                f"Set INACTIVE={self.MAX_INACTIVE_DAYS} in {self.USERADD_DEFAULTS}"
            )
        elif useradd_config["inactive_days"] > self.MAX_INACTIVE_DAYS:
            issues.append(
                f"INACTIVE is set to {useradd_config['inactive_days']} days "
                f"(recommended: {self.MAX_INACTIVE_DAYS} or less)"
            )
            recommendations.append(
                f"Set INACTIVE={self.MAX_INACTIVE_DAYS} in {self.USERADD_DEFAULTS}"
            )
        elif useradd_config["inactive_days"] < 0:
            issues.append("INACTIVE is set to -1 (never lock inactive accounts)")
            recommendations.append(
                f"Set INACTIVE={self.MAX_INACTIVE_DAYS} in {self.USERADD_DEFAULTS}"
            )

        # Check shadow entries for users without inactive setting
        if shadow_config["users_no_inactive"]:
            issues.append(
                f"{len(shadow_config['users_no_inactive'])} user(s) have no inactive lock configured"
            )
            recommendations.append(
                "Use 'chage -I 30 <username>' to set inactive lock for existing users"
            )

        # Check for users exceeding limit
        if shadow_config["users_exceeding_limit"]:
            users_list = ", ".join([
                f"{u['username']}({u['inactive_days']}d)" 
                for u in shadow_config["users_exceeding_limit"][:5]
            ])
            if len(shadow_config["users_exceeding_limit"]) > 5:
                users_list += "..."
            issues.append(
                f"{len(shadow_config['users_exceeding_limit'])} user(s) exceed "
                f"{self.MAX_INACTIVE_DAYS} day limit: {users_list}"
            )
            recommendations.append(
                f"Use 'chage -I {self.MAX_INACTIVE_DAYS} <username>' to reduce inactive lock period"
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Inactive password lock has issues: {'; '.join(issues[:3])}",
                remediation=(
                    "Configure inactive password lock:\n\n"
                    + "\n".join(recommendations)
                    + "\n\nTo set default for new users, edit /etc/default/useradd:\n"
                    f"INACTIVE={self.MAX_INACTIVE_DAYS}\n\n"
                    "To update existing users:\n"
                    f"chage -I {self.MAX_INACTIVE_DAYS} <username>\n\n"
                    "To update all users at once:\n"
                    "awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd | "
                    f"xargs -I {{}} chage -I {self.MAX_INACTIVE_DAYS} {{}}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check passed - verify we have some configuration
        inactive_days = useradd_config["inactive_days"]
        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Inactive password lock is properly configured (INACTIVE={inactive_days})",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
