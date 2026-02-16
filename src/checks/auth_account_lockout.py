"""
CIS Audit Check: Account Lockout Policy

Checks if account lockout is configured using PAM faillock module
to prevent brute force attacks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AccountLockoutCheck(BaseCheck):
    """Check for account lockout configuration using PAM faillock."""

    id = "auth_account_lockout"
    name = "Account Lockout Policy"
    description = (
        "Verifies that account lockout is configured using PAM faillock "
        "to prevent brute force password attacks"
    )
    severity = Severity.HIGH
    requires_root = True

    # Files to check
    PAM_AUTH_CONFIGS = [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    FAILLOCK_CONF = "/etc/security/faillock.conf"
    FAILLOCK_D_DIR = "/etc/security/faillock.conf.d"

    def _check_pam_faillock(self) -> tuple[bool, dict]:
        """Check if pam_faillock is configured in PAM.

        Returns:
            Tuple of (configured, details)
        """
        details = {
            "files_checked": [],
            "auth_lines": [],
            "account_lines": [],
            "preauth_found": False,
            "authfail_found": False,
            "account_found": False,
        }

        for pam_file in self.PAM_AUTH_CONFIGS:
            if not os.path.exists(pam_file):
                continue

            details["files_checked"].append(pam_file)

            try:
                with open(pam_file, "r") as f:
                    for line in f:
                        line_stripped = line.strip()
                        if not line_stripped or line_stripped.startswith("#"):
                            continue

                        # Check for pam_faillock.so in auth phase
                        if "pam_faillock.so" in line_stripped:
                            if "auth" in line_stripped:
                                details["auth_lines"].append(f"{pam_file}: {line_stripped}")
                                if "preauth" in line_stripped:
                                    details["preauth_found"] = True
                                if "authfail" in line_stripped:
                                    details["authfail_found"] = True
                            if "account" in line_stripped:
                                details["account_lines"].append(f"{pam_file}: {line_stripped}")
                                details["account_found"] = True

            except (IOError, OSError) as e:
                details.setdefault("errors", []).append(f"{pam_file}: {str(e)}")

        configured = details["preauth_found"] and details["authfail_found"] and details["account_found"]
        return configured, details

    def _check_faillock_config(self) -> dict:
        """Check faillock.conf for lockout settings.

        Returns:
            Dictionary with configuration values found
        """
        config = {
            "deny": None,
            "unlock_time": None,
            "fail_interval": None,
            "even_deny_root": False,
            "root_unlock_time": None,
            "files_read": [],
        }

        # Read main config file
        if os.path.exists(self.FAILLOCK_CONF):
            config["files_read"].append(self.FAILLOCK_CONF)
            try:
                with open(self.FAILLOCK_CONF, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        # Check for deny
                        match = re.match(r"^deny\s*=\s*(\d+)", line)
                        if match:
                            config["deny"] = int(match.group(1))

                        # Check for unlock_time
                        match = re.match(r"^unlock_time\s*=\s*(\d+)", line)
                        if match:
                            config["unlock_time"] = int(match.group(1))

                        # Check for fail_interval
                        match = re.match(r"^fail_interval\s*=\s*(\d+)", line)
                        if match:
                            config["fail_interval"] = int(match.group(1))

                        # Check for even_deny_root
                        if re.match(r"^even_deny_root\b", line):
                            config["even_deny_root"] = True

                        # Check for root_unlock_time
                        match = re.match(r"^root_unlock_time\s*=\s*(\d+)", line)
                        if match:
                            config["root_unlock_time"] = int(match.group(1))

            except (IOError, OSError):
                pass

        # Check faillock.conf.d directory
        if os.path.isdir(self.FAILLOCK_D_DIR):
            try:
                for conf_file in sorted(Path(self.FAILLOCK_D_DIR).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                match = re.match(r"^deny\s*=\s*(\d+)", line)
                                if match:
                                    config["deny"] = int(match.group(1))

                                match = re.match(r"^unlock_time\s*=\s*(\d+)", line)
                                if match:
                                    config["unlock_time"] = int(match.group(1))

                                match = re.match(r"^fail_interval\s*=\s*(\d+)", line)
                                if match:
                                    config["fail_interval"] = int(match.group(1))

                                if re.match(r"^even_deny_root\b", line):
                                    config["even_deny_root"] = True

                                match = re.match(r"^root_unlock_time\s*=\s*(\d+)", line)
                                if match:
                                    config["root_unlock_time"] = int(match.group(1))

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the account lockout check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check for PAM faillock configuration
        pam_configured, pam_details = self._check_pam_faillock()

        if not pam_configured:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="PAM faillock is not properly configured for account lockout",
                remediation=(
                    "Configure PAM faillock in /etc/pam.d/system-auth and /etc/pam.d/password-auth:\n\n"
                    "Add these lines to the 'auth' section (before pam_unix.so):\n"
                    "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n"
                    "auth required pam_faillock.so authfail audit deny=5 unlock_time=900\n\n"
                    "Add this line to the 'account' section:\n"
                    "account required pam_faillock.so\n\n"
                    "Then configure /etc/security/faillock.conf:\n"
                    "deny = 5\n"
                    "unlock_time = 900\n"
                    "fail_interval = 900\n"
                    "even_deny_root\n"
                    "root_unlock_time = 900"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=pam_details,
            )

        # Check faillock configuration
        faillock_config = self._check_faillock_config()

        # Validate configuration
        issues = []
        recommendations = []

        if faillock_config["deny"] is None:
            issues.append("deny limit is not configured (recommended: 5 or less)")
            recommendations.append("Set deny = 5 in /etc/security/faillock.conf")
        elif faillock_config["deny"] > 5:
            issues.append(f"deny limit is {faillock_config['deny']} (recommended: 5 or less)")
            recommendations.append("Set deny = 5 in /etc/security/faillock.conf")

        if faillock_config["unlock_time"] is None:
            issues.append("unlock_time is not configured (recommended: 900 seconds or more)")
            recommendations.append("Set unlock_time = 900 in /etc/security/faillock.conf")
        elif faillock_config["unlock_time"] < 900:
            issues.append(f"unlock_time is {faillock_config['unlock_time']} seconds (recommended: 900+)")
            recommendations.append("Set unlock_time = 900 in /etc/security/faillock.conf")

        if not faillock_config["even_deny_root"]:
            issues.append("even_deny_root is not enabled")
            recommendations.append("Add 'even_deny_root' to /etc/security/faillock.conf")

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Account lockout is configured but has weak settings: {'; '.join(issues)}",
                remediation=(
                    "Strengthen account lockout configuration in /etc/security/faillock.conf:\n"
                    + "\n".join(recommendations)
                    + "\n\nRecommended configuration:\n"
                    "deny = 5\n"
                    "unlock_time = 900\n"
                    "fail_interval = 900\n"
                    "even_deny_root\n"
                    "root_unlock_time = 900"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "pam_config": pam_details,
                    "faillock_config": faillock_config,
                },
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"Account lockout is properly configured "
                f"(deny={faillock_config['deny']}, unlock_time={faillock_config['unlock_time']}s, "
                f"even_deny_root={faillock_config['even_deny_root']})"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "pam_config": pam_details,
                "faillock_config": faillock_config,
            },
        )
