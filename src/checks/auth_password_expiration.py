"""
CIS Audit Check: Password Expiration Policy

Checks if password expiration policies are properly configured
in /etc/login.defs.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class PasswordExpirationCheck(BaseCheck):
    """Check for password expiration policy configuration."""

    id = "auth_password_expiration"
    name = "Password Expiration Policy"
    description = (
        "Verifies that password expiration policies are properly configured "
        "in /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE)"
    )
    severity = Severity.MEDIUM
    requires_root = True

    LOGIN_DEFS = "/etc/login.defs"

    # CIS recommended values
    RECOMMENDED_MAX_DAYS = 90
    RECOMMENDED_MIN_DAYS = 7
    RECOMMENDED_WARN_AGE = 7

    def _parse_login_defs(self) -> dict:
        """Parse /etc/login.defs for password expiration settings.

        Returns:
            Dictionary with password policy values
        """
        config = {
            "PASS_MAX_DAYS": None,
            "PASS_MIN_DAYS": None,
            "PASS_WARN_AGE": None,
            "file_read": False,
        }

        if not os.path.exists(self.LOGIN_DEFS):
            return config

        try:
            with open(self.LOGIN_DEFS, "r") as f:
                config["file_read"] = True
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Check for PASS_MAX_DAYS
                    match = re.match(r"^PASS_MAX_DAYS\s+(\d+)", line)
                    if match:
                        config["PASS_MAX_DAYS"] = int(match.group(1))

                    # Check for PASS_MIN_DAYS
                    match = re.match(r"^PASS_MIN_DAYS\s+(\d+)", line)
                    if match:
                        config["PASS_MIN_DAYS"] = int(match.group(1))

                    # Check for PASS_WARN_AGE
                    match = re.match(r"^PASS_WARN_AGE\s+(\d+)", line)
                    if match:
                        config["PASS_WARN_AGE"] = int(match.group(1))

        except (IOError, OSError) as e:
            config["error"] = str(e)

        return config

    def run(self) -> CheckResult:
        """Execute the password expiration check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_login_defs()

        # Check if file was readable
        if not config["file_read"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cannot read {self.LOGIN_DEFS}",
                remediation=f"Ensure {self.LOGIN_DEFS} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Check for errors
        if "error" in config:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Error reading {self.LOGIN_DEFS}: {config['error']}",
                remediation="Check file permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Validate settings
        issues = []
        recommendations = []

        # Check PASS_MAX_DAYS
        if config["PASS_MAX_DAYS"] is None:
            issues.append("PASS_MAX_DAYS is not set (recommended: 90 or less)")
            recommendations.append(
                f"Set PASS_MAX_DAYS {self.RECOMMENDED_MAX_DAYS} in {self.LOGIN_DEFS}"
            )
        elif config["PASS_MAX_DAYS"] > self.RECOMMENDED_MAX_DAYS:
            issues.append(
                f"PASS_MAX_DAYS is {config['PASS_MAX_DAYS']} (recommended: {self.RECOMMENDED_MAX_DAYS} or less)"
            )
            recommendations.append(
                f"Set PASS_MAX_DAYS to {self.RECOMMENDED_MAX_DAYS} in {self.LOGIN_DEFS}"
            )
        elif config["PASS_MAX_DAYS"] == 0:
            issues.append("PASS_MAX_DAYS is 0 (passwords never expire)")
            recommendations.append(
                f"Set PASS_MAX_DAYS to {self.RECOMMENDED_MAX_DAYS} in {self.LOGIN_DEFS}"
            )

        # Check PASS_MIN_DAYS
        if config["PASS_MIN_DAYS"] is None:
            issues.append("PASS_MIN_DAYS is not set (recommended: 7 or more)")
            recommendations.append(
                f"Set PASS_MIN_DAYS {self.RECOMMENDED_MIN_DAYS} in {self.LOGIN_DEFS}"
            )
        elif config["PASS_MIN_DAYS"] < self.RECOMMENDED_MIN_DAYS:
            issues.append(
                f"PASS_MIN_DAYS is {config['PASS_MIN_DAYS']} (recommended: {self.RECOMMENDED_MIN_DAYS} or more)"
            )
            recommendations.append(
                f"Set PASS_MIN_DAYS to {self.RECOMMENDED_MIN_DAYS} in {self.LOGIN_DEFS}"
            )

        # Check PASS_WARN_AGE
        if config["PASS_WARN_AGE"] is None:
            issues.append("PASS_WARN_AGE is not set (recommended: 7 or more)")
            recommendations.append(
                f"Set PASS_WARN_AGE {self.RECOMMENDED_WARN_AGE} in {self.LOGIN_DEFS}"
            )
        elif config["PASS_WARN_AGE"] < self.RECOMMENDED_WARN_AGE:
            issues.append(
                f"PASS_WARN_AGE is {config['PASS_WARN_AGE']} (recommended: {self.RECOMMENDED_WARN_AGE} or more)"
            )
            recommendations.append(
                f"Set PASS_WARN_AGE to {self.RECOMMENDED_WARN_AGE} in {self.LOGIN_DEFS}"
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Password expiration policy has issues: {'; '.join(issues)}",
                remediation=(
                    "Update /etc/login.defs with the following settings:\n"
                    + "\n".join(recommendations)
                    + "\n\nRecommended configuration:\n"
                    f"PASS_MAX_DAYS   {self.RECOMMENDED_MAX_DAYS}\n"
                    f"PASS_MIN_DAYS   {self.RECOMMENDED_MIN_DAYS}\n"
                    f"PASS_WARN_AGE   {self.RECOMMENDED_WARN_AGE}\n\n"
                    "Note: Existing users will not be affected until their password is changed. "
                    "Use 'chage' to update existing users."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"Password expiration policy is properly configured "
                f"(PASS_MAX_DAYS={config['PASS_MAX_DAYS']}, "
                f"PASS_MIN_DAYS={config['PASS_MIN_DAYS']}, "
                f"PASS_WARN_AGE={config['PASS_WARN_AGE']})"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
