"""
CIS Audit Check: Password Complexity Requirements

Checks if password complexity requirements are configured using
pam_pwquality or pam_cracklib modules.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class PasswordComplexityCheck(BaseCheck):
    """Check for password complexity configuration in PAM."""

    id = "auth_password_complexity"
    name = "Password Complexity Requirements"
    description = (
        "Verifies that password complexity requirements are configured "
        "using pam_pwquality or pam_cracklib in PAM configuration"
    )
    severity = Severity.HIGH
    requires_root = True

    # Files to check
    PAM_PASSWORD_CONFIGS = [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/common-password",
    ]
    PWQUALITY_CONF = "/etc/security/pwquality.conf"
    PWQUALITY_D_DIR = "/etc/security/pwquality.conf.d"

    def _check_pam_module(self) -> tuple[bool, str, dict]:
        """Check if pam_pwquality or pam_cracklib is configured in PAM.

        Returns:
            Tuple of (found, module_name, details)
        """
        details = {"files_checked": [], "module_found": None, "config_lines": []}

        for pam_file in self.PAM_PASSWORD_CONFIGS:
            if not os.path.exists(pam_file):
                continue

            details["files_checked"].append(pam_file)

            try:
                with open(pam_file, "r") as f:
                    content = f.read()

                # Check for pam_pwquality
                if re.search(r"pam_pwquality\.so", content):
                    details["module_found"] = "pam_pwquality"
                    # Extract the line(s) with pam_pwquality
                    for line in content.split("\n"):
                        if "pam_pwquality" in line and not line.strip().startswith("#"):
                            details["config_lines"].append(f"{pam_file}: {line.strip()}")
                    return True, "pam_pwquality", details

                # Check for pam_cracklib (fallback)
                if re.search(r"pam_cracklib\.so", content):
                    details["module_found"] = "pam_cracklib"
                    for line in content.split("\n"):
                        if "pam_cracklib" in line and not line.strip().startswith("#"):
                            details["config_lines"].append(f"{pam_file}: {line.strip()}")
                    return True, "pam_cracklib", details

            except (IOError, OSError) as e:
                details.setdefault("errors", []).append(f"{pam_file}: {str(e)}")

        return False, None, details

    def _check_pwquality_config(self) -> dict:
        """Check pwquality.conf for complexity settings.

        Returns:
            Dictionary with configuration values found
        """
        config = {
            "minlen": None,
            "minclass": None,
            "dcredit": None,
            "ucredit": None,
            "lcredit": None,
            "ocredit": None,
            "files_read": [],
        }

        # Read main config file
        if os.path.exists(self.PWQUALITY_CONF):
            config["files_read"].append(self.PWQUALITY_CONF)
            try:
                with open(self.PWQUALITY_CONF, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        for key in ["minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit"]:
                            match = re.match(rf"^{key}\s*=\s*(\S+)", line)
                            if match:
                                try:
                                    config[key] = int(match.group(1))
                                except ValueError:
                                    config[key] = match.group(1)
            except (IOError, OSError):
                pass

        # Check pwquality.conf.d directory
        if os.path.isdir(self.PWQUALITY_D_DIR):
            try:
                for conf_file in sorted(Path(self.PWQUALITY_D_DIR).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                for key in ["minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit"]:
                                    match = re.match(rf"^{key}\s*=\s*(\S+)", line)
                                    if match:
                                        try:
                                            config[key] = int(match.group(1))
                                        except ValueError:
                                            config[key] = match.group(1)
                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the password complexity check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check for PAM module
        module_found, module_name, pam_details = self._check_pam_module()

        if not module_found:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No password complexity module (pam_pwquality or pam_cracklib) is configured in PAM",
                remediation=(
                    "Install and configure pam_pwquality:\n"
                    "1. Install: dnf install libpwquality\n"
                    "2. Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth\n"
                    "3. Add/replace password line with:\n"
                    "   password requisite pam_pwquality.so try_first_pass local_users_only retry=3\n"
                    "4. Configure complexity in /etc/security/pwquality.conf:\n"
                    "   minlen = 14\n"
                    "   minclass = 4\n"
                    "   dcredit = -1\n"
                    "   ucredit = -1\n"
                    "   lcredit = -1\n"
                    "   ocredit = -1"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=pam_details,
            )

        # If pam_pwquality is found, check its configuration
        if module_name == "pam_pwquality":
            pwq_config = self._check_pwquality_config()

            # Check for minimum requirements
            issues = []
            recommendations = []

            if pwq_config["minlen"] is None or pwq_config["minlen"] < 14:
                issues.append(f"minlen is {pwq_config['minlen'] or 'not set'} (recommended: 14+)")
                recommendations.append("Set minlen = 14 in /etc/security/pwquality.conf")

            if pwq_config["minclass"] is None or pwq_config["minclass"] < 3:
                issues.append(f"minclass is {pwq_config['minclass'] or 'not set'} (recommended: 3+)")
                recommendations.append("Set minclass = 3 or 4 in /etc/security/pwquality.conf")

            if issues:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message=f"pam_pwquality is configured but has weak settings: {'; '.join(issues)}",
                    remediation=(
                        "Strengthen password complexity in /etc/security/pwquality.conf:\n"
                        + "\n".join(recommendations)
                        + "\n\nExample configuration:\n"
                        "minlen = 14\n"
                        "minclass = 4\n"
                        "dcredit = -1\n"
                        "ucredit = -1\n"
                        "lcredit = -1\n"
                        "ocredit = -1"
                    ),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details={
                        "pam_config": pam_details,
                        "pwquality_config": pwq_config,
                    },
                )

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Password complexity is properly configured with pam_pwquality (minlen={pwq_config['minlen']}, minclass={pwq_config['minclass']})",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "pam_config": pam_details,
                    "pwquality_config": pwq_config,
                },
            )

        # pam_cracklib found (less common on modern systems)
        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Password complexity module {module_name} is configured (pam_pwquality is recommended for Fedora)",
            severity=self.severity,
            requires_root=self.requires_root,
            details=pam_details,
        )
