"""
CIS Audit Check: Password Reuse Limit (5.3.3)

Ensures password reuse is limited by configuring pam_pwhistory
in PAM to remember previous passwords.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class PasswordReuseCheck(BaseCheck):
    """Check for password reuse limitation using pam_pwhistory."""

    id = "auth_password_reuse"
    name = "Password Reuse Limit"
    description = (
        "Verifies that password reuse is limited by configuring "
        "pam_pwhistory in PAM to remember at least 24 previous passwords"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Files to check
    PAM_CONFIGS = [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    MIN_REMEMBER = 24

    def _check_pam_pwhistory(self) -> tuple[bool, dict]:
        """Check if pam_pwhistory is configured in PAM.

        Returns:
            Tuple of (configured, details)
        """
        details = {
            "files_checked": [],
            "pwhistory_lines": [],
            "remember_value": None,
        }

        for pam_file in self.PAM_CONFIGS:
            if not os.path.exists(pam_file):
                continue

            details["files_checked"].append(pam_file)

            try:
                with open(pam_file, "r") as f:
                    for line in f:
                        line_stripped = line.strip()
                        if not line_stripped or line_stripped.startswith("#"):
                            continue

                        # Check for pam_pwhistory.so in password phase
                        if "pam_pwhistory.so" in line_stripped:
                            details["pwhistory_lines"].append(f"{pam_file}: {line_stripped}")
                            
                            # Extract remember value
                            match = re.search(r"remember=(\d+)", line_stripped)
                            if match:
                                remember = int(match.group(1))
                                if details["remember_value"] is None or remember > details["remember_value"]:
                                    details["remember_value"] = remember

            except (IOError, OSError) as e:
                details.setdefault("errors", []).append(f"{pam_file}: {str(e)}")

        configured = len(details["pwhistory_lines"]) > 0
        return configured, details

    def run(self) -> CheckResult:
        """Execute the password reuse limit check.

        Returns:
            CheckResult with the outcome of the check
        """
        configured, details = self._check_pam_pwhistory()

        if not configured:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="pam_pwhistory is not configured in PAM",
                remediation=(
                    "Configure pam_pwhistory in /etc/pam.d/system-auth and /etc/pam.d/password-auth:\n\n"
                    "Add the following line to the password section (before pam_unix.so):\n"
                    f"password required pam_pwhistory.so use_authtok remember={self.MIN_REMEMBER}\n\n"
                    "Example configuration:\n"
                    "password requisite pam_pwquality.so try_first_pass local_users_only retry=3\n"
                    f"password required pam_pwhistory.so use_authtok remember={self.MIN_REMEMBER}\n"
                    "password sufficient pam_unix.so try_first_pass use_authtok nullok sha512 shadow\n\n"
                    "This ensures users cannot reuse their last 24 passwords."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if remember value meets minimum
        remember = details["remember_value"]
        if remember is None:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="pam_pwhistory is configured but remember parameter is not set",
                remediation=(
                    f"Add remember={self.MIN_REMEMBER} to the pam_pwhistory configuration:\n\n"
                    "password required pam_pwhistory.so use_authtok remember=24"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if remember < self.MIN_REMEMBER:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"pam_pwhistory remember value is {remember} (recommended: {self.MIN_REMEMBER} or more)",
                remediation=(
                    f"Increase the remember parameter to {self.MIN_REMEMBER}:\n\n"
                    f"password required pam_pwhistory.so use_authtok remember={self.MIN_REMEMBER}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Password reuse is limited with pam_pwhistory (remember={remember})",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
