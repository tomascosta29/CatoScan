"""
CIS Audit Check: SELinux Policy Configured

Checks that SELinux policy is configured (targeted or mls).
CIS 1.5.1.3
"""

import os
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxPolicyCheck(BaseCheck):
    """Check that SELinux policy is properly configured."""

    id = "selinux_policy"
    name = "SELinux Policy Configured"
    description = (
        "Verifies that SELinux policy is configured to use either "
        "targeted or mls policy type"
    )
    severity = Severity.HIGH
    requires_root = True

    SELINUX_CONFIG = "/etc/selinux/config"
    VALID_POLICIES = ["targeted", "mls"]

    def _read_selinux_config(self) -> dict:
        """Read SELinux configuration file.

        Returns:
            Dictionary with configuration values
        """
        config = {
            "file_exists": False,
            "selinux": None,
            "selinuxtype": None,
            "raw_lines": [],
        }

        if not os.path.exists(self.SELINUX_CONFIG):
            return config

        config["file_exists"] = True

        try:
            with open(self.SELINUX_CONFIG, "r") as f:
                for line in f:
                    line = line.strip()
                    config["raw_lines"].append(line)

                    if line.startswith("#") or not line:
                        continue

                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')

                        if key == "SELINUX":
                            config["selinux"] = value.lower()
                        elif key == "SELINUXTYPE":
                            config["selinuxtype"] = value.lower()

        except (IOError, OSError) as e:
            config["error"] = str(e)

        return config

    def run(self) -> CheckResult:
        """Execute the SELinux policy check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_selinux_config()

        if not config["file_exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"SELinux configuration file not found: {self.SELINUX_CONFIG}",
                remediation=(
                    f"Create {self.SELINUX_CONFIG} with proper SELinux configuration:\n"
                    f"SELINUX=enforcing\n"
                    f"SELINUXTYPE=targeted"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if config.get("error"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Error reading SELinux configuration: {config['error']}",
                remediation="Check file permissions and try again",
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        policy_type = config.get("selinuxtype")

        if not policy_type:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="SELINUXTYPE is not configured in /etc/selinux/config",
                remediation=(
                    f"Set SELINUXTYPE in {self.SELINUX_CONFIG}:\n"
                    f"SELINUXTYPE=targeted\n\n"
                    f"Valid options: {', '.join(self.VALID_POLICIES)}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        if policy_type not in self.VALID_POLICIES:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Invalid SELINUXTYPE configured: {policy_type}",
                remediation=(
                    f"Set SELINUXTYPE to a valid policy in {self.SELINUX_CONFIG}:\n"
                    f"SELINUXTYPE=targeted\n\n"
                    f"Valid options: {', '.join(self.VALID_POLICIES)}"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=config,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"SELinux policy is properly configured: SELINUXTYPE={policy_type}",
            severity=self.severity,
            requires_root=self.requires_root,
            details=config,
        )
