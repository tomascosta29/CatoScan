"""
CIS Audit Check: SSH Ciphers (5.1.13)

Ensures only strong ciphers are used for SSH connections.
Weak ciphers should be disabled to prevent cryptographic attacks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHCiphersCheck(BaseCheck):
    """Check SSH Ciphers configuration."""

    id = "ssh_ciphers"
    name = "SSH Ciphers"
    description = (
        "Verifies that only strong ciphers are used for SSH connections "
        "and weak ciphers are disabled"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

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

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for Ciphers setting.

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
        if os.path.exists(self.SSHD_CONFIG):
            config["files_read"].append(self.SSHD_CONFIG)
            try:
                with open(self.SSHD_CONFIG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        match = re.match(r"^Ciphers\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["ciphers"] = value
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
            "configured_ciphers": [],
            "weak_ciphers_found": [],
            "has_weak_ciphers": False,
        }

        # Parse cipher list
        ciphers = [c.strip() for c in cipher_string.split(",") if c.strip()]
        result["configured_ciphers"] = ciphers

        # Check for weak ciphers
        for cipher in ciphers:
            # Handle negation (e.g., -3des-cbc)
            if cipher.startswith("-") or cipher.startswith("!"):
                continue  # This is explicitly disabled

            # Remove any + or @ suffixes for comparison
            base_cipher = cipher.split("+")[0].split("@")[0]

            if cipher.lower() in self.WEAK_CIPHERS or base_cipher.lower() in self.WEAK_CIPHERS:
                result["weak_ciphers_found"].append(cipher)
                result["has_weak_ciphers"] = True

        return result

    def run(self) -> CheckResult:
        """Execute the SSH Ciphers check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        if not config["files_read"]:
            # Default cipher list in modern OpenSSH is secure
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "Ciphers not explicitly configured. Modern OpenSSH defaults "
                    "to secure cipher suites."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config["ciphers"] is None:
            # Not explicitly set - modern defaults are secure
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "Ciphers directive not found. Modern OpenSSH defaults "
                    "to secure cipher suites."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        cipher_analysis = self._check_ciphers(config["ciphers"])

        if cipher_analysis["has_weak_ciphers"]:
            weak_list = ", ".join(cipher_analysis["weak_ciphers_found"])
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Weak ciphers detected: {weak_list}",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n"
                    f"Ciphers {','.join(self.RECOMMENDED_CIPHERS)}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "Weak ciphers are vulnerable to cryptographic attacks. "
                    "Use only modern, authenticated encryption ciphers."
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
            message="SSH is configured to use strong ciphers only",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "config": config,
                "cipher_analysis": cipher_analysis,
            },
        )
