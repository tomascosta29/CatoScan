"""
CIS Audit Check: Audit DAC Permission Changes (4.4.11)

Checks if audit rules are configured to monitor DAC permission changes.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditDACChangesCheck(BaseCheck):
    """Check for audit rules monitoring DAC permission changes."""

    id = "audit_dac_changes"
    name = "Audit DAC Permission Changes"
    description = (
        "Verifies that audit rules are configured to monitor changes to "
        "Discretionary Access Control (DAC) permissions including chmod, chown, "
        "fchmod, fchown, lchown, and related syscalls"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # DAC-related syscalls to check
    DAC_SYSCALLS = [
        "chmod", "fchmod", "fchmodat",
        "chown", "fchown", "lchown", "fchownat",
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

    def _check_dac_rules(self, rules: list[str]) -> dict:
        """Check for DAC-related audit rules."""
        findings = {
            "chmod_monitored": False,
            "chown_monitored": False,
            "fchmod_monitored": False,
            "fchown_monitored": False,
            "lchown_monitored": False,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for chmod-related syscalls
            if re.search(r"\bchmod\b|\bfchmod\b|\bfchmodat\b", rule, re.IGNORECASE):
                findings["chmod_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            # Check for chown-related syscalls
            if re.search(r"\bchown\b|\bfchown\b|\blchown\b|\bfchownat\b", rule, re.IGNORECASE):
                findings["chown_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the DAC changes audit check."""
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
                    "Configure audit rules to monitor DAC permission changes:\n\n"
                    "1. Create /etc/audit/rules.d/dac.rules:\n\n"
                    "   # Monitor DAC permission changes (64-bit)\n"
                    "   -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod\n"
                    "   -a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k perm_mod\n\n"
                    "   # Monitor DAC permission changes (32-bit)\n"
                    "   -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod\n"
                    "   -a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -k perm_mod\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep perm_mod"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_dac_rules(rules)
        details.update(findings)

        # Check for essential DAC monitoring
        if not findings["chmod_monitored"] or not findings["chown_monitored"]:
            missing = []
            if not findings["chmod_monitored"]:
                missing.append("chmod/chmod family syscalls")
            if not findings["chown_monitored"]:
                missing.append("chown/chown family syscalls")

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Missing DAC permission audit rules: {', '.join(missing)}",
                remediation=(
                    f"Add missing DAC audit rules to /etc/audit/rules.d/dac.rules:\n\n"
                    f"Missing: {', '.join(missing)}\n\n"
                    f"Add these rules:\n"
                    f"-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod\n"
                    f"-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k perm_mod\n\n"
                    f"Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor DAC permission changes",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
