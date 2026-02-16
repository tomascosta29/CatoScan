"""
CIS Audit Check: Audit File Deletion Events (4.4.13)

Checks if audit rules are configured to monitor file deletion events.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditFileDeletionsCheck(BaseCheck):
    """Check for audit rules monitoring file deletion events."""

    id = "audit_file_deletions"
    name = "Audit File Deletion Events"
    description = (
        "Verifies that audit rules are configured to monitor file "
        "deletion events by users including unlink, unlinkat, rename, renameat, "
        "and related syscalls"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # File deletion-related syscalls
    DELETION_SYSCALLS = ["unlink", "unlinkat", "rename", "renameat", "rmdir"]

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

    def _check_deletion_rules(self, rules: list[str]) -> dict:
        """Check for file deletion-related audit rules."""
        findings = {
            "unlink_monitored": False,
            "rename_monitored": False,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for unlink syscalls
            if re.search(r"\bunlink\b|\bunlinkat\b", rule, re.IGNORECASE):
                findings["unlink_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            # Check for rename syscalls (can be used to overwrite files)
            if re.search(r"\brename\b|\brenameat\b", rule, re.IGNORECASE):
                findings["rename_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the file deletion events audit check."""
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
                    "Configure audit rules to monitor file deletion events:\n\n"
                    "1. Create /etc/audit/rules.d/deletions.rules:\n\n"
                    "   # Monitor file deletion events (64-bit)\n"
                    "   -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete\n\n"
                    "   # Monitor file deletion events (32-bit)\n"
                    "   -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep delete"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_deletion_rules(rules)
        details.update(findings)

        # Check for deletion monitoring
        if not findings["unlink_monitored"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules configured for file deletion events",
                remediation=(
                    "Add file deletion audit rules to /etc/audit/rules.d/deletions.rules:\n\n"
                    "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete\n"
                    "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete\n\n"
                    "Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor file deletion events",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
