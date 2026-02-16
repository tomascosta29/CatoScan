"""
CIS Audit Check: SSH Client Ciphers (5.2.x)

Ensures SSH client is configured to use only strong ciphers.
Weak ciphers should be disabled to prevent cryptographic attacks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientCiphersCheck(BaseCheck):
    """Check SSH client Ciphers configuration."""

    id = "ssh_client_ciphers"
    name = "SSH Client Ciphers"
    description = (
        "Verifies that SSH client is configured to use only strong ciphers "
        "and weak ciphers are disabled"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    # Weak ciphers that should not be used
    WEAK_CIPHERS = {
        "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
        "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
    }

    # Recommended strong ciphers
    RECOMMENDED_CIPHERS = [
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    ]

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for Ciphers setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "ciphers": None,
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

                        match = re.match(r"^Ciphers\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["ciphers"] = value
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

                                match = re.match(r"^Ciphers\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["ciphers"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_ciphers(self, cipher_string: str) -> dict:
        """Check if the cipher string contains weak ciphers.

        Args:
            cipher_string: Comma-separated list of ciphers

        Returns:
            Dictionary with analysis results
        """
        result = {
            "configured": [],
            "weak_found": [],
            "has_weak": False,
        }

        # Parse cipher list
        ciphers = [c.strip() for c in cipher_string.split(",") if c.strip()]
        result["configured"] = ciphers

        # Check for weak ciphers
        for cipher in ciphers:
            # Handle negation (e.g., -3des-cbc)
            if cipher.startswith("-") or cipher.startswith("!"):
                continue  # This is explicitly disabled

            if cipher.lower() in self.WEAK_CIPHERS:
                result["weak_found"].append(cipher)
                result["has_weak"] = True

        return result

    def run(self) -> CheckResult:
        """Execute the SSH client ciphers check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if config["ciphers"] is None:
            # Not explicitly set - modern defaults are secure
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "Ciphers directive not found in SSH client config. "
                    "Modern OpenSSH defaults to secure ciphers."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        cipher_analysis = self._check_ciphers(config["ciphers"])

        if cipher_analysis["has_weak"]:
            weak_list = ", ".join(cipher_analysis["weak_found"])
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Weak ciphers detected: {weak_list}",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    f"Ciphers {','.join(self.RECOMMENDED_CIPHERS)}\n\n"
                    "Weak ciphers are vulnerable to cryptographic attacks. "
                    "Use only modern, authenticated encryption algorithms."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "config": config,
                    "cipher_analysis": cipher_analysis,
                    "recommended": self.RECOMMENDED_CIPHERS,
                },
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="SSH client is configured to use strong ciphers",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "config": config,
                "cipher_analysis": cipher_analysis,
            },
        )
