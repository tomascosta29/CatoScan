"""
CIS Audit Check: SSH Warning Banner (5.1.18)

Ensures a warning banner is configured for SSH connections.
This provides legal notice and deters unauthorized access attempts.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHBannerCheck(BaseCheck):
    """Check SSH warning banner configuration."""

    id = "ssh_banner"
    name = "SSH Warning Banner"
    description = (
        "Verifies that a warning banner is configured for SSH connections "
        "to provide legal notice and deter unauthorized access"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for Banner setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "banner": None,
            "config_file": None,
            "config_line": None,
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

                        match = re.match(r"^Banner\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["banner"] = value
                            config["config_file"] = self.SSHD_CONFIG
                            config["config_line"] = line

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

                                match = re.match(r"^Banner\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["banner"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_banner_file(self, banner_path: str) -> dict:
        """Check if the banner file exists and has content.

        Args:
            banner_path: Path to the banner file

        Returns:
            Dictionary with file check results
        """
        result = {
            "path": banner_path,
            "exists": False,
            "has_content": False,
            "size": 0,
        }

        # Handle 'none' value
        if banner_path.lower() == "none":
            result["is_none"] = True
            return result

        result["is_none"] = False

        try:
            if os.path.exists(banner_path):
                result["exists"] = True
                result["size"] = os.path.getsize(banner_path)
                result["has_content"] = result["size"] > 0
        except (IOError, OSError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the SSH banner check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if config["banner"] is None:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Banner directive not configured - no warning banner is displayed",
                remediation=(
                    "Edit /etc/ssh/sshd_config and set:\n"
                    "Banner /etc/issue.net\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "Ensure /etc/issue.net contains an appropriate warning message.\n"
                    "Example warning banner:\n"
                    "\"Authorized access only. All activity may be monitored and reported.\""
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        banner_value = config["banner"]
        banner_check = self._check_banner_file(banner_value)

        if banner_check.get("is_none"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Banner is set to 'none' - no warning banner is displayed",
                remediation=(
                    f"Edit {config['config_file']} and set:\n"
                    "Banner /etc/issue.net\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "Ensure /etc/issue.net contains an appropriate warning message."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"config": config, "banner_file": banner_check},
            )

        if not banner_check["exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Banner file does not exist: {banner_value}",
                remediation=(
                    f"Create the banner file:\n"
                    f"echo 'Authorized access only. All activity may be monitored and reported.' > {banner_value}\n\n"
                    f"Or update {config['config_file']} to point to an existing file:\n"
                    "Banner /etc/issue.net"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"config": config, "banner_file": banner_check},
            )

        if not banner_check["has_content"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Banner file is empty: {banner_value}",
                remediation=(
                    f"Add content to the banner file:\n"
                    f"echo 'Authorized access only. All activity may be monitored and reported.' > {banner_value}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"config": config, "banner_file": banner_check},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"SSH warning banner is configured: {banner_value} ({banner_check['size']} bytes)",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"config": config, "banner_file": banner_check},
        )
