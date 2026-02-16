"""
CIS Audit Check: SSH Ciphers and MACs (5.1.x)

Ensures only strong ciphers and MACs are used for SSH connections.
Weak algorithms should be disabled to prevent cryptographic attacks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHCiphersMACCheck(BaseCheck):
    """Check SSH Ciphers and MACs configuration."""

    id = "ssh_ciphers_mac"
    name = "SSH Ciphers and MACs"
    description = (
        "Verifies that only strong ciphers and MAC algorithms are used "
        "for SSH connections and weak algorithms are disabled"
    )
    severity = Severity.HIGH
    requires_root = True

    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"

    # Weak ciphers that should not be used
    WEAK_CIPHERS = {
        "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
        "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
    }

    # Weak MACs that should not be used
    WEAK_MACS = {
        "hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96",
        "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
        "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
        "umac-64@openssh.com", "umac-128@openssh.com",
        "umac-64-etm@openssh.com",
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

    # Recommended strong MACs
    RECOMMENDED_MACS = [
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ]

    def _parse_sshd_config(self) -> dict:
        """Parse SSH daemon configuration for Ciphers and MACs.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "ciphers": None,
            "macs": None,
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

                        match = re.match(r"^Ciphers\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "directive": "Ciphers",
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            config["ciphers"] = value
                            config["config_file"] = self.SSHD_CONFIG

                        match = re.match(r"^MACs\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "directive": "MACs",
                                "file": self.SSHD_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            config["macs"] = value
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

                                match = re.match(r"^Ciphers\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "directive": "Ciphers",
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    config["ciphers"] = value
                                    config["config_file"] = str(conf_file)

                                match = re.match(r"^MACs\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "directive": "MACs",
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    config["macs"] = value
                                    config["config_file"] = str(conf_file)

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_algorithms(self, algo_string: str, weak_algos: set) -> dict:
        """Check if the algorithm string contains weak algorithms.

        Args:
            algo_string: Comma-separated list of algorithms
            weak_algos: Set of weak algorithms to check against

        Returns:
            Dictionary with analysis results
        """
        result = {
            "configured": [],
            "weak_found": [],
            "has_weak": False,
        }

        # Parse algorithm list
        algos = [a.strip() for a in algo_string.split(",") if a.strip()]
        result["configured"] = algos

        # Check for weak algorithms
        for algo in algos:
            # Handle negation (e.g., -3des-cbc)
            if algo.startswith("-") or algo.startswith("!"):
                continue  # This is explicitly disabled

            if algo.lower() in weak_algos:
                result["weak_found"].append(algo)
                result["has_weak"] = True

        return result

    def run(self) -> CheckResult:
        """Execute the SSH Ciphers and MACs check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_sshd_config()

        issues = []
        cipher_analysis = None
        mac_analysis = None

        # Check Ciphers
        if config["ciphers"] is not None:
            cipher_analysis = self._check_algorithms(config["ciphers"], self.WEAK_CIPHERS)
            if cipher_analysis["has_weak"]:
                weak_list = ", ".join(cipher_analysis["weak_found"])
                issues.append(f"Weak ciphers: {weak_list}")
        else:
            # Not explicitly set - modern defaults are secure
            pass

        # Check MACs
        if config["macs"] is not None:
            mac_analysis = self._check_algorithms(config["macs"], self.WEAK_MACS)
            if mac_analysis["has_weak"]:
                weak_list = ", ".join(mac_analysis["weak_found"])
                issues.append(f"Weak MACs: {weak_list}")
        else:
            # Not explicitly set - modern defaults are secure
            pass

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="; ".join(issues),
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/sshd_config'} and set:\n\n"
                    f"Ciphers {','.join(self.RECOMMENDED_CIPHERS)}\n"
                    f"MACs {','.join(self.RECOMMENDED_MACS)}\n\n"
                    "Then reload SSH:\n"
                    "systemctl reload sshd\n\n"
                    "Weak algorithms are vulnerable to cryptographic attacks. "
                    "Use only modern, authenticated encryption and MAC algorithms."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "config": config,
                    "cipher_analysis": cipher_analysis,
                    "mac_analysis": mac_analysis,
                    "recommended_ciphers": self.RECOMMENDED_CIPHERS,
                    "recommended_macs": self.RECOMMENDED_MACS,
                },
            )

        # Check passed
        if config["ciphers"] is not None and config["macs"] is not None:
            msg = "SSH is configured to use strong ciphers and MACs"
        elif config["ciphers"] is not None:
            msg = "SSH is configured to use strong ciphers; MACs use secure defaults"
        elif config["macs"] is not None:
            msg = "SSH is configured to use strong MACs; ciphers use secure defaults"
        else:
            msg = "SSH uses secure default ciphers and MACs"

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=msg,
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "config": config,
                "cipher_analysis": cipher_analysis,
                "mac_analysis": mac_analysis,
            },
        )
