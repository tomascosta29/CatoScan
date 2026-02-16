"""
CIS Audit Check: Audit Sudo Command Execution (4.4.15)

Checks if audit rules are configured to monitor sudo command execution.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditSudoLogCheck(BaseCheck):
    """Check for audit rules monitoring sudo command execution."""

    id = "audit_sudolog"
    name = "Audit Sudo Command Execution"
    description = (
        "Verifies that audit rules are configured to monitor sudo "
        "command execution and privilege escalation events"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    SUDO_BINARIES = [
        "/usr/bin/sudo",
        "/bin/sudo",
        "/usr/bin/sudoedit",
        "/usr/sbin/sudo",
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

    def _check_sudo_execution_rules(self, rules: list[str]) -> dict:
        """Check for sudo execution-related audit rules."""
        findings = {
            "sudo_binary_monitored": False,
            "sudo_execution_logged": False,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for sudo binary monitoring (watch rules)
            if re.search(r"/usr/bin/sudo\b|/bin/sudo\b", rule, re.IGNORECASE):
                findings["sudo_binary_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            # Check for sudo execution via syscall auditing
            if re.search(r"execve.*sudo|sudo.*execve", rule, re.IGNORECASE):
                findings["sudo_execution_logged"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the sudo execution audit check."""
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
                    "Configure audit rules to monitor sudo command execution:\n\n"
                    "1. Create /etc/audit/rules.d/sudo-execution.rules:\n\n"
                    "   # Monitor sudo command execution\n"
                    "   -w /usr/bin/sudo -p x -k privilege_escalation\n"
                    "   -w /usr/bin/sudoedit -p x -k privilege_escalation\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep privilege_escalation"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_sudo_execution_rules(rules)
        details.update(findings)

        # Check for sudo execution monitoring
        if not findings["sudo_binary_monitored"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules configured for sudo command execution",
                remediation=(
                    "Add sudo execution audit rules to /etc/audit/rules.d/sudo-execution.rules:\n\n"
                    "-w /usr/bin/sudo -p x -k privilege_escalation\n"
                    "-w /usr/bin/sudoedit -p x -k privilege_escalation\n\n"
                    "Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor sudo command execution",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
