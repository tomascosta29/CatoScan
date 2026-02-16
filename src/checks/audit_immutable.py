"""
CIS Audit Check: Audit Configuration Immutable (4.4.17)

Checks if audit rules are configured to make the audit configuration immutable.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditImmutableCheck(BaseCheck):
    """Check for audit configuration immutability."""

    id = "audit_immutable"
    name = "Audit Configuration Immutable"
    description = (
        "Verifies that audit rules are configured to make the audit "
        "configuration immutable, preventing unauthorized changes to audit rules "
        "without a system reboot"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    def _parse_rules_from_file(self, file_path: str) -> list[str]:
        """Parse audit rules from a file."""
        rules = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
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

    def _check_immutable_rule(self, rules: list[str]) -> dict:
        """Check for the immutable audit rule."""
        findings = {
            "immutable_configured": False,
            "matching_rule": None,
            "immutable_line_number": None,
        }

        for i, rule in enumerate(rules):
            # Check for -e 2 (immutable) rule
            if re.search(r"^\s*-e\s+2\s*$", rule):
                findings["immutable_configured"] = True
                findings["matching_rule"] = rule
                findings["immutable_line_number"] = i + 1
                break

        return findings

    def run(self) -> CheckResult:
        """Execute the audit immutable configuration check."""
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
                    "Configure audit rules and make them immutable:\n\n"
                    "1. Create /etc/audit/rules.d/99-finalize.rules:\n\n"
                    "   # Make audit configuration immutable\n"
                    "   # This rule must be at the end of the file\n"
                    "   -e 2\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -s | grep enabled\n\n"
                    "Note: Once -e 2 is set, audit rules cannot be changed without a reboot."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_immutable_rule(rules)
        details.update(findings)

        if not findings["immutable_configured"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Audit configuration is not set to immutable (-e 2)",
                remediation=(
                    "Add the immutable rule to /etc/audit/rules.d/99-finalize.rules:\n\n"
                    "# Make audit configuration immutable\n"
                    "# This rule must be at the end of the file\n"
                    "-e 2\n\n"
                    "Then reload: augenrules --load\n\n"
                    "Note: Once -e 2 is set, audit rules cannot be changed without a reboot."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit configuration is set to immutable (-e 2)",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
