"""
CIS Audit Check: SSH AllowUsers/AllowGroups (5.1.20)

Ensures SSH access is restricted to specific users or groups.
This limits the attack surface by only allowing authorized users.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHAllowUsersCheck(BaseCheck):
    """Check SSH AllowUsers and AllowGroups configuration."""

    id = "ssh_allow_users"
    name = "SSH AllowUsers/AllowGroups"
    description = (
        "Verifies that SSH access is restricted to specific users or groups "
        "to limit the attack surface and prevent unauthorized access"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for AllowUsers/AllowGroups.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "allow_users": [],
            "allow_groups": [],
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

                        # Check for AllowUsers
                        match = re.match(r"^AllowUsers\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "directive": "AllowUsers",
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Multiple AllowUsers lines are cumulative
                            users = [u.strip() for u in value.split() if u.strip()]
                            config["allow_users"].extend(users)
                            if config["config_file"] is None:
                                config["config_file"] = self.SSHD_CONFIG

                        # Check for AllowGroups
                        match = re.match(r"^AllowGroups\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "directive": "AllowGroups",
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Multiple AllowGroups lines are cumulative
                            groups = [g.strip() for g in value.split() if g.strip()]
                            config["allow_groups"].extend(groups)
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

                                # Check for AllowUsers
                                match = re.match(r"^AllowUsers\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "directive": "AllowUsers",
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    users = [u.strip() for u in value.split() if u.strip()]
                                    config["allow_users"].extend(users)
                                    config["config_file"] = str(conf_file)

                                # Check for AllowGroups
                                match = re.match(r"^AllowGroups\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "directive": "AllowGroups",
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    groups = [g.strip() for g in value.split() if g.strip()]
                                    config["allow_groups"].extend(groups)
                                    config["config_file"] = str(conf_file)

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def run(self) -> CheckResult:
        """Execute the SSH AllowUsers/AllowGroups check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        has_allow_users = len(config["allow_users"]) > 0
        has_allow_groups = len(config["allow_groups"]) > 0

        if has_allow_users or has_allow_groups:
            details = []
            if has_allow_users:
                details.append(f"AllowUsers: {', '.join(config['allow_users'])}")
            if has_allow_groups:
                details.append(f"AllowGroups: {', '.join(config['allow_groups'])}")

            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH access is restricted: " + "; ".join(details),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # Neither AllowUsers nor AllowGroups is configured
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="Neither AllowUsers nor AllowGroups is configured - all users can attempt SSH access",
            remediation=(
                "Edit /etc/ssh/sshd_config and add one or both directives:\n\n"
                "# Allow specific users:\n"
                "AllowUsers user1 user2@192.168.1.0/24 user3@10.0.0.*\n\n"
                "# Or allow specific groups:\n"
                "AllowGroups sshusers wheel\n\n"
                "Then reload SSH:\n"
                "systemctl reload sshd\n\n"
                "Restricting SSH access to specific users or groups limits the "
                "attack surface and prevents unauthorized access attempts."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
