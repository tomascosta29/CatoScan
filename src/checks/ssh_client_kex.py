"""
CIS Audit Check: SSH Client Key Exchange Algorithms (5.2.x)

Ensures SSH client is configured to use only strong Key Exchange algorithms.
Weak KEX algorithms should be disabled to prevent cryptographic attacks.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SSHClientKexCheck(BaseCheck):
    """Check SSH client KexAlgorithms configuration."""

    id = "ssh_client_kex"
    name = "SSH Client Key Exchange Algorithms"
    description = (
        "Verifies that SSH client is configured to use only strong Key Exchange algorithms "
        "and weak algorithms are disabled"
    )
    severity = Severity.MEDIUM
    requires_root = True

    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_CONFIG_D = "/etc/ssh/ssh_config.d"

    # Weak KEX algorithms that should not be used
    WEAK_KEX = {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    }

    # Recommended strong KEX algorithms
    RECOMMENDED_KEX = [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp521",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ]

    def _parse_ssh_config(self) -> dict:
        """Parse SSH client configuration for KexAlgorithms setting.

        Returns:
            Dictionary with configuration details
        """
        config = {
            "kex_algorithms": None,
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

                        match = re.match(r"^KexAlgorithms\s+(.+)", line, re.IGNORECASE)
                        if match:
                            value = match.group(1).strip()
                            config["all_settings"].append({
                                "file": self.SSH_CONFIG,
                                "value": value,
                                "line": line,
                            })
                            # Last setting wins
                            config["kex_algorithms"] = value
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

                                match = re.match(r"^KexAlgorithms\s+(.+)", line, re.IGNORECASE)
                                if match:
                                    value = match.group(1).strip()
                                    config["all_settings"].append({
                                        "file": str(conf_file),
                                        "value": value,
                                        "line": line,
                                    })
                                    # Last setting wins
                                    config["kex_algorithms"] = value
                                    config["config_file"] = str(conf_file)
                                    config["config_line"] = line

                    except (IOError, OSError):
                        pass
            except (IOError, OSError):
                pass

        return config

    def _check_kex(self, kex_string: str) -> dict:
        """Check if the KEX string contains weak algorithms.

        Args:
            kex_string: Comma-separated list of KEX algorithms

        Returns:
            Dictionary with analysis results
        """
        result = {
            "configured": [],
            "weak_found": [],
            "has_weak": False,
        }

        # Parse algorithm list
        algos = [a.strip() for a in kex_string.split(",") if a.strip()]
        result["configured"] = algos

        # Check for weak algorithms
        for algo in algos:
            # Handle negation (e.g., -diffie-hellman-group1-sha1)
            if algo.startswith("-") or algo.startswith("!"):
                continue  # This is explicitly disabled

            if algo.lower() in self.WEAK_KEX:
                result["weak_found"].append(algo)
                result["has_weak"] = True

        return result

    def run(self) -> CheckResult:
        """Execute the SSH client Key Exchange algorithms check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._parse_ssh_config()

        if config["kex_algorithms"] is None:
            # Not explicitly set - modern defaults are secure
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    "KexAlgorithms directive not found in SSH client config. "
                    "Modern OpenSSH defaults to secure Key Exchange algorithms."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        kex_analysis = self._check_kex(config["kex_algorithms"])

        if kex_analysis["has_weak"]:
            weak_list = ", ".join(kex_analysis["weak_found"])
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Weak Key Exchange algorithms detected: {weak_list}",
                remediation=(
                    f"Edit {config['config_file'] or '/etc/ssh/ssh_config'} and set:\n"
                    f"KexAlgorithms {','.join(self.RECOMMENDED_KEX)}\n\n"
                    "Weak Key Exchange algorithms are vulnerable to cryptographic attacks. "
                    "Use only modern, secure KEX algorithms like curve25519-sha256."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "config": config,
                    "kex_analysis": kex_analysis,
                    "recommended": self.RECOMMENDED_KEX,
                },
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="SSH client is configured to use strong Key Exchange algorithms",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "config": config,
                "kex_analysis": kex_analysis,
            },
        )
