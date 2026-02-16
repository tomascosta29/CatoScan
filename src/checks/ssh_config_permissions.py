"""
CIS Audit Check: SSH Configuration File Permissions (5.1.1-5.1.3)

Checks permissions and ownership of SSH configuration files and host keys.
- 5.1.1: Ensure permissions on /etc/ssh/sshd_config are configured
- 5.1.2: Ensure permissions on SSH private host key files are configured
- 5.1.3: Ensure permissions on SSH public host key files are configured
"""

import os
import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHConfigPermissionsCheck(BaseCheck):
    """Check SSH configuration file permissions."""

    id = "ssh_config_permissions"
    name = "SSH Configuration File Permissions"
    description = (
        "Verifies that SSH configuration files and host keys have "
        "appropriate permissions and ownership"
    )
    severity = Severity.HIGH
    requires_root = True

    SSH_CONFIG = "/etc/ssh/sshd_config"
    SSH_CONFIG_D = "/etc/ssh/sshd_config.d"
    SSH_DIR = "/etc/ssh"

    def _check_file_permissions(self, filepath: str, expected_mode: int, expected_owner: int = 0) -> dict:
        """Check file permissions and ownership.

        Args:
            filepath: Path to the file
            expected_mode: Expected file mode (e.g., 0o600)
            expected_owner: Expected owner UID (0 for root)

        Returns:
            Dictionary with check results
        """
        result = {
            "path": filepath,
            "exists": False,
            "mode_ok": False,
            "owner_ok": False,
            "group_ok": False,
            "actual_mode": None,
            "actual_owner": None,
            "actual_group": None,
        }

        try:
            st = os.stat(filepath)
            result["exists"] = True
            result["actual_mode"] = stat.S_IMODE(st.st_mode)
            result["actual_owner"] = st.st_uid
            result["actual_group"] = st.st_gid

            # Check mode (should be exact or more restrictive)
            result["mode_ok"] = (result["actual_mode"] & expected_mode) == expected_mode

            # Check owner (should be root)
            result["owner_ok"] = st.st_uid == expected_owner

            # Check group (should be root or ssh/ssh_keys)
            result["group_ok"] = st.st_gid == 0 or st.st_gid in [50, 51]  # root, ssh, ssh_keys

        except (IOError, OSError):
            pass

        return result

    def _check_sshd_config(self) -> dict:
        """Check /etc/ssh/sshd_config permissions.

        Returns:
            Dictionary with check results
        """
        # CIS: 5.1.1 - should be 600 (owner read/write only)
        result = self._check_file_permissions(self.SSH_CONFIG, 0o600)
        result["check"] = "sshd_config"
        result["cis"] = "5.1.1"
        result["expected_mode"] = 0o600
        return result

    def _check_private_host_keys(self) -> list[dict]:
        """Check SSH private host key permissions.

        Returns:
            List of check results for each private key
        """
        results = []
        ssh_dir = Path(self.SSH_DIR)

        if not ssh_dir.exists():
            return results

        # Find all private host keys (ssh_host_*_key, not .pub)
        for key_file in ssh_dir.glob("ssh_host_*_key"):
            if key_file.suffix == ".pub":
                continue

            # CIS: 5.1.2 - should be 600 (owner read/write only)
            result = self._check_file_permissions(str(key_file), 0o600)
            result["check"] = "private_host_key"
            result["cis"] = "5.1.2"
            result["expected_mode"] = 0o600
            results.append(result)

        return results

    def _check_public_host_keys(self) -> list[dict]:
        """Check SSH public host key permissions.

        Returns:
            List of check results for each public key
        """
        results = []
        ssh_dir = Path(self.SSH_DIR)

        if not ssh_dir.exists():
            return results

        # Find all public host keys (ssh_host_*_key.pub)
        for key_file in ssh_dir.glob("ssh_host_*_key.pub"):
            # CIS: 5.1.3 - should be 644 (readable by all)
            result = self._check_file_permissions(str(key_file), 0o644)
            result["check"] = "public_host_key"
            result["cis"] = "5.1.3"
            result["expected_mode"] = 0o644
            results.append(result)

        return results

    def run(self) -> CheckResult:
        """Execute the SSH config permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if SSH is installed
        if not os.path.exists(self.SSH_DIR):
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH directory does not exist - SSH may not be installed",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"ssh_dir": self.SSH_DIR},
            )

        # Run all checks
        sshd_config_check = self._check_sshd_config()
        private_key_checks = self._check_private_host_keys()
        public_key_checks = self._check_public_host_keys()

        all_checks = [sshd_config_check] + private_key_checks + public_key_checks

        # Analyze results
        failed_checks = []

        # Check sshd_config
        if not sshd_config_check["exists"]:
            failed_checks.append(f"{sshd_config_check['cis']}: {self.SSH_CONFIG} does not exist")
        else:
            if not sshd_config_check["mode_ok"]:
                failed_checks.append(
                    f"{sshd_config_check['cis']}: {self.SSH_CONFIG} has mode "
                    f"{oct(sshd_config_check['actual_mode'])} (expected {oct(sshd_config_check['expected_mode'])} or more restrictive)"
                )
            if not sshd_config_check["owner_ok"]:
                failed_checks.append(
                    f"{sshd_config_check['cis']}: {self.SSH_CONFIG} is owned by UID "
                    f"{sshd_config_check['actual_owner']} (expected root)"
                )

        # Check private keys
        for check in private_key_checks:
            if not check["exists"]:
                continue  # Skip non-existent keys
            if not check["mode_ok"]:
                failed_checks.append(
                    f"{check['cis']}: {check['path']} has mode "
                    f"{oct(check['actual_mode'])} (expected {oct(check['expected_mode'])} or more restrictive)"
                )
            if not check["owner_ok"]:
                failed_checks.append(
                    f"{check['cis']}: {check['path']} is owned by UID "
                    f"{check['actual_owner']} (expected root)"
                )

        # Check public keys
        for check in public_key_checks:
            if not check["exists"]:
                continue
            if not check["mode_ok"]:
                failed_checks.append(
                    f"{check['cis']}: {check['path']} has mode "
                    f"{oct(check['actual_mode'])} (expected {oct(check['expected_mode'])})"
                )
            if not check["owner_ok"]:
                failed_checks.append(
                    f"{check['cis']}: {check['path']} is owned by UID "
                    f"{check['actual_owner']} (expected root)"
                )

        if failed_checks:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="; ".join(failed_checks),
                remediation=(
                    "Fix SSH file permissions:\n"
                    "5.1.1: chmod 600 /etc/ssh/sshd_config\n"
                    "       chown root:root /etc/ssh/sshd_config\n"
                    "5.1.2: chmod 600 /etc/ssh/ssh_host_*_key\n"
                    "       chown root:root /etc/ssh/ssh_host_*_key\n"
                    "5.1.3: chmod 644 /etc/ssh/ssh_host_*_key.pub\n"
                    "       chown root:root /etc/ssh/ssh_host_*_key.pub"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "sshd_config": sshd_config_check,
                    "private_keys": private_key_checks,
                    "public_keys": public_key_checks,
                },
            )

        # Count checked files
        private_key_count = len([c for c in private_key_checks if c["exists"]])
        public_key_count = len([c for c in public_key_checks if c["exists"]])

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"All SSH file permissions are correct: "
                f"sshd_config (5.1.1), {private_key_count} private keys (5.1.2), "
                f"{public_key_count} public keys (5.1.3)"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "sshd_config": sshd_config_check,
                "private_keys": private_key_checks,
                "public_keys": public_key_checks,
            },
        )
