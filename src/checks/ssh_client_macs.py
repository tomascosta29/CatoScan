"""
CIS Audit Check: SSH Client MACs (5.2.x)

Ensures SSH client is configured to use only strong MAC algorithms.
Weak MACs should be disabled to prevent cryptographic attacks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientMACsCheck(BaseCheck):
    """Check SSH client MACs configuration."""

    id = "ssh_client_macs"
    name = "SSH Client MACs"
    description = (
        "Verifies that SSH client is configured to use only strong MAC algorithms "
        "and weak MACs are disabled"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    # Weak MACs that should not be used
    WEAK_MACS = {
        "hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96",
        "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
        "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-64-etm@openssh.com",
    }

    # Recommended strong MACs
    RECOMMENDED_MACS = [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ]

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for MACs setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "macs": None,
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

                        match = re.match(r"^MACs\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["macs"] = value
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

                                match = re.match(r"^MACs\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["macs"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_macs(self, mac_string: str) -> dict:
        """Check if the MAC string contains weak algorithms.

        Args:
            mac_string: Comma-separated list of MAC algorithms

        Returns:
            Dictionary with analysis results
        """
        result = {
            "configured": [],
            "weak_found": [],
            "has_weak": False,
        }

        # Parse MAC list
        macs = [m.strip() for m in mac_string.split(",") if m.strip()]
        result["configured"] = macs

        # Check for weak MACs
        for mac in macs:
            # Handle negation (e.g., -hmac-md5)
            if mac.startswith("-") or mac.startswith("!"):
                continue  # This is explicitly disabled

            if mac.lower() in self.WEAK_MACS:
                result["weak_found"].append(mac)
                result["has_weak"] = True

        return result

    def run(self) -> CheckResult:
        """Execute the SSH client MACs check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if config["macs"] is None:
            # Not explicitly set - modern defaults are secure
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "MACs directive not found in SSH client config. "
                    "Modern OpenSSH defaults to secure MAC algorithms."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        mac_analysis = self._check_macs(config["macs"])

        if mac_analysis["has_weak"]:
            weak_list = ", ".join(mac_analysis["weak_found"])
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Weak MAC algorithms detected: {weak_list}",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    f"MACs {','.join(self.RECOMMENDED_MACS)}\n\n"
                    "Weak MAC algorithms are vulnerable to cryptographic attacks. "
                    "Use only modern, secure MAC algorithms."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "config": config,
                    "mac_analysis": mac_analysis,
                    "recommended": self.RECOMMENDED_MACS,
                },
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="SSH client is configured to use strong MAC algorithms",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "config": config,
                "mac_analysis": mac_analysis,
            },
        )
