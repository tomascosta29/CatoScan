"""
CIS Audit Check: Audit Filesystem Mounts (4.4.12)

Checks if audit rules are configured to monitor filesystem mount operations.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditMountsCheck(BaseCheck):
    """Check for audit rules monitoring filesystem mount operations."""

    id = "audit_mounts"
    name = "Audit Filesystem Mounts"
    description = (
        "Verifies that audit rules are configured to monitor filesystem "
        "mount and unmount operations including mount, umount, and umount2 syscalls"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # Mount-related syscalls
    MOUNT_SYSCALLS = ["mount", "umount", "umount2"]

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

    def _check_mount_rules(self, rules: list[str]) -> dict:
        """Check for mount-related audit rules."""
        findings = {
            "mount_monitored": False,
            "umount_monitored": False,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for mount syscall
            if re.search(r"\bmount\b", rule, re.IGNORECASE):
                findings["mount_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            # Check for umount syscalls
            if re.search(r"\bumount\b|\bumount2\b", rule, re.IGNORECASE):
                findings["umount_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the mount operations audit check."""
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
                    "Configure audit rules to monitor filesystem mount operations:\n\n"
                    "1. Create /etc/audit/rules.d/mounts.rules:\n\n"
                    "   # Monitor mount operations (64-bit)\n"
                    "   -a always,exit -F arch=b64 -S mount -S umount -S umount2 -k mounts\n\n"
                    "   # Monitor mount operations (32-bit)\n"
                    "   -a always,exit -F arch=b32 -S mount -S umount -S umount2 -k mounts\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep mounts"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_mount_rules(rules)
        details.update(findings)

        # Check for mount monitoring
        if not findings["mount_monitored"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules configured for filesystem mount operations",
                remediation=(
                    "Add mount audit rules to /etc/audit/rules.d/mounts.rules:\n\n"
                    "-a always,exit -F arch=b64 -S mount -S umount -S umount2 -k mounts\n"
                    "-a always,exit -F arch=b32 -S mount -S umount -S umount2 -k mounts\n\n"
                    "Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor filesystem mount operations",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
