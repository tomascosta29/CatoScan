"""
CIS Audit Check: SSH DenyUsers/DenyGroups (5.1.21)

Ensures specific users or groups are explicitly denied SSH access.
This provides an additional layer of access control.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHDenyUsersCheck(BaseCheck):
    """Check SSH DenyUsers and DenyGroups configuration."""

    id = "ssh_deny_users"
    name = "SSH DenyUsers/DenyGroups"
    description = (
        "Verifies that specific users or groups are explicitly denied "
        "SSH access to provide additional access control"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    # Default system accounts that should be denied SSH access
    DEFAULT_DENIED_USERS = [
        "root",  # Root should use su/sudo, not direct SSH
    ]

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for DenyUsers/DenyGroups.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "deny_users": [],
            "deny_groups": [],
            "config_file": None,
            "files_read": [],
            "all_settings": [],
        }

        # Read main config file first
        if os.path.exists(self.SSHD_CONFIG):
            config["files_read"].append(self.SSHD_CONFIG)
            try:
                with open(self.SSHD_CONFIG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        # Check for DenyUsers
                        match = re.match(r"^DenyUsers\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "directive": "DenyUsers",
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Multiple DenyUsers lines are cumulative
                            users = [u.strip() for u in value.split() if u.strip()]
                            config["deny_users"].extend(users)
                            if config["config_file"] is None:
                                config["config_file"] = self.SSHD_CONFIG

                        # Check for DenyGroups
                        match = re.match(r"^DenyGroups\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "directive": "DenyGroups",
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Multiple DenyGroups lines are cumulative
                            groups = [g.strip() for g in value.split() if g.strip()]
                            config["deny_groups"].extend(groups)
                            if config["config_file"] is None:
                                config["config_file"] = self.SSHD_CONFIG

            except (IOError, OSError):
                pass

        # Read config snippets from sshd_config.d (these override main config)
        if os.path.isdir(self.SSHD_CONFIG_D):
            try:
                for conf_file in sorted(Path(self.SSHD_CONFIG_D).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                # Check for DenyUsers
                                match = re.match(r"^DenyUsers\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "directive": "DenyUsers",
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    users = [u.strip() for u in value.split() if u.strip()]
                                    config["deny_users"].extend(users)
                                    config["config_file"] = str(conf_file)

                                # Check for DenyGroups
                                match = re.match(r"^DenyGroups\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "directive": "DenyGroups",
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    groups = [g.strip() for g in value.split() if g.strip()]
                                    config["deny_groups"].extend(groups)
                                    config["config_file"] = str(conf_file)

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_root_denied(self, deny_users: list) -> bool:
        """Check if root is explicitly denied.

        Args:
            deny_users: List of denied users

        Returns:
            True if root is denied
        """
        for user in deny_users:
            if user.lower() == "root":
                return True
        return False

    def run(self) -> CheckResult:
        """Execute the SSH DenyUsers/DenyGroups check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        has_deny_users = len(config["deny_users"]) > 0
        has_deny_groups = len(config["deny_groups"]) > 0

        if has_deny_users or has_deny_groups:
            details = []
            if has_deny_users:
                details.append(f"DenyUsers: {', '.join(config['deny_users'])}")
            if has_deny_groups:
                details.append(f"DenyGroups: {', '.join(config['deny_groups'])}")

            # Check if root is explicitly denied (good practice)
            root_denied = self._check_root_denied(config["deny_users"])

            if root_denied:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="SSH access denial is configured (root explicitly denied): " + "; ".join(details),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=config,
                )

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH access denial is configured: " + "; ".join(details),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Neither DenyUsers nor DenyGroups is configured
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="Neither DenyUsers nor DenyGroups is configured - no explicit SSH access denials",
            remediation=(
                "Edit /etc/ssh/sshd_config and add one or both directives:\n\n"
                "# Deny specific users (recommended to deny root):\n"
                "DenyUsers root\n\n"
                "# Or deny specific groups:\n"
                "DenyGroups nogroup guests\n\n"
                "Then reload SSH:\n"
                "systemctl reload sshd\n\n"
                "Explicitly denying SSH access for certain users (especially root) "
                "provides defense in depth. Note: root access should also be controlled "
                "via PermitRootLogin."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
