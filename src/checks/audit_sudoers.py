"""
CIS Audit Check: Audit Sudoers Changes (4.4.14)

Checks if audit rules are configured to monitor sudoers file changes.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditSudoersCheck(BaseCheck):
    """Check for audit rules monitoring sudoers configuration changes."""

    id = "audit_sudoers"
    name = "Audit Sudoers Changes"
    description = (
        "Verifies that audit rules are configured to monitor changes to "
        "sudoers configuration files (/etc/sudoers and /etc/sudoers.d)"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    SUDOERS_FILES = [
        "/etc/sudoers",
        "/etc/sudoers.d",
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

    def _check_sudoers_rules(self, rules: list[str]) -> dict:
        """Check for sudoers-related audit rules."""
        findings = {
            "sudoers_monitored": False,
            "sudoers_d_monitored": False,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for /etc/sudoers monitoring
            if re.search(r"/etc/sudoers\b", rule, re.IGNORECASE) and not re.search(r"/etc/sudoers\.d", rule, re.IGNORECASE):
                findings["sudoers_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            # Check for /etc/sudoers.d directory monitoring
            if re.search(r"/etc/sudoers\.d", rule, re.IGNORECASE):
                findings["sudoers_d_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the sudoers changes audit check."""
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
                    "Configure audit rules to monitor sudoers changes:\n\n"
                    "1. Create /etc/audit/rules.d/sudoers.rules:\n\n"
                    "   # Monitor sudoers configuration\n"
                    "   -w /etc/sudoers -p wa -k scope\n"
                    "   -w /etc/sudoers.d/ -p wa -k scope\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep scope"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_sudoers_rules(rules)
        details.update(findings)

        # Check for sudoers monitoring
        if not findings["sudoers_monitored"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules configured for sudoers file changes",
                remediation=(
                    "Add sudoers audit rules to /etc/audit/rules.d/sudoers.rules:\n\n"
                    "-w /etc/sudoers -p wa -k scope\n"
                    "-w /etc/sudoers.d/ -p wa -k scope\n\n"
                    "Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor sudoers configuration changes",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
