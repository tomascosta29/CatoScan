"""
CIS Audit Check: SSH Client SendEnv (5.2.x)

Ensures SSH client SendEnv is disabled to prevent
sending environment variables to the server.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientUserEnvCheck(BaseCheck):
    """Check SSH client SendEnv configuration."""

    id = "ssh_client_user_env"
    name = "SSH Client SendEnv"
    description = (
        "Verifies that SSH client SendEnv is disabled "
        "to prevent sending environment variables to the server"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for SendEnv setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "sendenv": [],
            "config_file": None,
            "config_line": None,
            "files_read": [],
            "all_settings": [],
        }

        # Read main config file first
        if os.path.exists(self.SSH_CONFIG):
            config["files_read"].append(self.SSH_CONFIG)
            try:
                with open(self.SSH_CONFIG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        match = re.match(r"^SendEnv\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Collect all SendEnv settings
                            config["sendenv"].append({
                                "value": value,
                                "file": self.SSH_CONFIG,
                                "line": line,
                            })
                            config["config_file"] = self.SSH_CONFIG
                            config["config_line"] = line

            except (IOError, OSError):
                pass

        # Read config snippets from ssh_config.d (these override main config)
        if os.path.isdir(self.SSH_CONFIG_D):
            try:
                for conf_file in sorted(Path(self.SSH_CONFIG_D).glob("*.conf")):
                    config["files_read"].append(str(conf_file))
                    try:
                        with open(conf_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue

                                match = re.match(r"^SendEnv\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Collect all SendEnv settings
                                    config["sendenv"].append({
                                        "value": value,
                                        "file": str(conf_file),
                                        "line": line,
                                    })
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _has_sendenv_enabled(self, config: dict) -> bool:
        """Check if SendEnv is enabled (not disabled).

        Args:
            config: Configuration dictionary

        Returns:
            True if SendEnv is enabled, False if disabled or not set
        """
        if not config["sendenv"]:
            return False  # Not set at all

        # Check if SendEnv is explicitly disabled
        for setting in config["sendenv"]:
            value = setting["value"].lower()
            # SendEnv with no arguments or "none" disables it
            if value == "" or value == "none":
                return False

        return True  # SendEnv is set to send some environment variables

    def run(self) -> CheckResult:
        """Execute the SSH client SendEnv check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if not config["sendenv"]:
            # Not explicitly set - check if there's a default
            # Modern OpenSSH may have SendEnv set by default in some distros
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "SendEnv directive not found in SSH client config. "
                    "Environment variables will not be sent to remote servers."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        sendenv_enabled = self._has_sendenv_enabled(config)

        if not sendenv_enabled:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="SSH client SendEnv is disabled - secure configuration",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        # SendEnv is enabled
        sendenv_values = [s["value"] for s in config["sendenv"]]
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"SSH client SendEnv is enabled: {', '.join(sendenv_values)}",
            remediation=(
                f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and remove or disable:\n"
                "SendEnv directives\n\n"
                "To disable SendEnv, either:\n"
                "1. Remove all SendEnv lines, or\n"
                "2. Add 'SendEnv none' or 'SendEnv' with no arguments\n\n"
                "Sending environment variables to remote servers can expose "
                "sensitive information and potentially be exploited."
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
