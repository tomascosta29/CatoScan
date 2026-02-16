"""
CIS Audit Check: Audit MAC (SELinux) Changes (4.4.10)

Checks if audit rules are configured to monitor SELinux configuration changes.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditMACChangesCheck(BaseCheck):
    """Check for audit rules monitoring SELinux/MAC configuration changes."""

    id = "audit_mac_changes"
    name = "Audit MAC (SELinux) Changes"
    description = (
        "Verifies that audit rules are configured to monitor changes to "
        "SELinux configuration and Mandatory Access Control (MAC) settings"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # SELinux-related files and patterns
    SELINUX_PATTERNS = [
        r"/etc/selinux",
        r"/etc/selinux/config",
        r"/etc/selinux/targeted",
        r"/etc/selinux/strict",
        r"/selinux",
        r"setenforce",
        r"selinux",
    ]

    def _parse_rules_from_file(self, file_path: str) -> list[str]:
        """Parse audit rules from a file."""
        rules = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("-"):
                        continue
                    rules.append(line)
        except (IOError, OSError):
            pass
        return rules

    def _collect_all_rules(self) -> list[str]:
        """Collect all audit rules from all sources."""
        all_rules = []
        if os.path.isdir(self.AUDIT_RULES_D_DIR):
            try:
                for rules_file in sorted(Path(self.AUDIT_RULES_D_DIR).glob("*.rules")):
                    all_rules.extend(self._parse_rules_from_file(str(rules_file)))
            except (IOError, OSError):
                pass
        if os.path.exists(self.AUDIT_RULES_FILE):
            all_rules.extend(self._parse_rules_from_file(self.AUDIT_RULES_FILE))
        return all_rules

    def _check_selinux_rules(self, rules: list[str]) -> dict:
        """Check for SELinux-related audit rules."""
        findings = {
            "selinux_config_monitored": False,
            "selinux_policy_monitored": False,
            "matching_rules": [],
        }

        for rule in rules:
            if re.search(r"/etc/selinux/config|/etc/selinux/config", rule, re.IGNORECASE):
                findings["selinux_config_monitored"] = True
                findings["matching_rules"].append(rule)
            if re.search(r"/etc/selinux/[^/]+/|/selinux", rule, re.IGNORECASE):
                findings["selinux_policy_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the SELinux/MAC changes audit check."""
        details = {
            "audit_rules_file_exists": os.path.exists(self.AUDIT_RULES_FILE),
            "audit_rules_d_exists": os.path.isdir(self.AUDIT_RULES_D_DIR),
        }

        rules = self._collect_all_rules()
        details["total_rules"] = len(rules)

        if not rules:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules are configured",
                remediation=(
                    "Configure audit rules to monitor SELinux configuration changes:\n\n"
                    "1. Create /etc/audit/rules.d/selinux.rules:\n\n"
                    "   # Monitor SELinux configuration\n"
                    "   -w /etc/selinux/ -p wa -k MAC-policy\n"
                    "   -w /etc/selinux/config -p wa -k MAC-policy\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep MAC-policy"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_selinux_rules(rules)
        details.update(findings)

        if not findings["selinux_config_monitored"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules configured for SELinux configuration changes",
                remediation=(
                    "Add SELinux audit rules to /etc/audit/rules.d/selinux.rules:\n\n"
                    "-w /etc/selinux/ -p wa -k MAC-policy\n"
                    "-w /etc/selinux/config -p wa -k MAC-policy\n\n"
                    "Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor SELinux/MAC configuration changes",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
