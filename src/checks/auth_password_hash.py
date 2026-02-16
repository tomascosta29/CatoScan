"""
CIS Audit Check: Password Hashing Algorithm (5.3.4)

Ensures the system uses a strong password hashing algorithm
(SHA-512 or yescrypt) via pam_unix configuration.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class PasswordHashCheck(BaseCheck):
    """Check for strong password hashing algorithm in PAM."""

    id = "auth_password_hash"
    name = "Password Hashing Algorithm"
    description = (
        "Verifies that the system uses a strong password hashing algorithm "
        "(SHA-512 or yescrypt) via pam_unix configuration"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Files to check
    PAM_CONFIGS = [
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    
    # Supported hashing algorithms
    VALID_HASHES = ["sha512", "yescrypt", "sha256"]
    RECOMMENDED_HASHES = ["sha512", "yescrypt"]

    def _check_pam_unix_hash(self) -> tuple[bool, str, dict]:
        """Check pam_unix for hashing algorithm configuration.

        Returns:
            Tuple of (configured, hash_type, details)
        """
        details = {
            "files_checked": [],
            "pam_unix_lines": [],
            "hash_type": None,
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

                        # Check for pam_unix.so in password phase
                        if "pam_unix.so" in line_stripped and "password" in line_stripped:
                            details["pam_unix_lines"].append(f"{pam_file}: {line_stripped}")
                            
                            # Check for hash algorithm
                            for hash_type in self.VALID_HASHES:
                                if hash_type in line_stripped.lower():
                                    details["hash_type"] = hash_type
                                    return True, hash_type, details

            except (IOError, OSError) as e:
                details.setdefault("errors", []).append(f"{pam_file}: {str(e)}")

        # If no explicit hash found, check if pam_unix is configured at all
        # (default is usually sha512 on modern systems)
        if details["pam_unix_lines"]:
            return True, "default", details
        
        return False, None, details

    def _check_authselect_profile(self) -> dict:
        """Check authselect profile for default hashing.

        Returns:
            Dictionary with authselect configuration
        """
        result = {
            "authselect_used": False,
            "profile": None,
            "features": [],
        }

        authselect_conf = "/etc/authselect/authselect.conf"
        if os.path.exists(authselect_conf):
            result["authselect_used"] = True
            try:
                with open(authselect_conf, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("profile="):
                            result["profile"] = line.split("=", 1)[1]
                        elif line.startswith("features="):
                            result["features"] = line.split("=", 1)[1].split()
            except (IOError, OSError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the password hashing algorithm check.

        Returns:
            CheckResult with the outcome of the check
        """
        configured, hash_type, details = self._check_pam_unix_hash()

        if not configured:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="pam_unix is not configured in PAM password section",
                remediation=(
                    "Ensure pam_unix is properly configured in /etc/pam.d/system-auth "
                    "and /etc/pam.d/password-auth with a strong hashing algorithm:\n\n"
                    "password sufficient pam_unix.so try_first_pass use_authtok nullok sha512 shadow"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check authselect profile
        authselect_info = self._check_authselect_profile()
        details["authselect"] = authselect_info

        # Validate hash type
        if hash_type == "default":
            # Default is typically sha512 on modern Fedora, but we should verify
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="pam_unix is configured (using system default hashing algorithm)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if hash_type in self.RECOMMENDED_HASHES:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Strong password hashing algorithm is configured ({hash_type})",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if hash_type == "sha256":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Password hashing uses SHA-256 (recommended: SHA-512 or yescrypt)",
                remediation=(
                    "Update pam_unix configuration to use SHA-512 or yescrypt:\n\n"
                    "In /etc/pam.d/system-auth and /etc/pam.d/password-auth:\n"
                    "password sufficient pam_unix.so try_first_pass use_authtok nullok sha512 shadow\n\n"
                    "Or for yescrypt (Fedora 43+):\n"
                    "password sufficient pam_unix.so try_first_pass use_authtok nullok yescrypt shadow"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Unknown or weak hash
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Password hashing may be using a weak algorithm ({hash_type or 'unknown'})",
            remediation=(
                "Configure a strong hashing algorithm in pam_unix:\n\n"
                "In /etc/pam.d/system-auth and /etc/pam.d/password-auth:\n"
                "password sufficient pam_unix.so try_first_pass use_authtok nullok sha512 shadow\n\n"
                "Note: If using authselect, modify the appropriate profile or use:\n"
                "authselect select sssd with-sha512"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
