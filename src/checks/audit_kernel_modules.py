"""
CIS Audit Check: Audit Kernel Module Load/Unload (4.4.16)

Checks if audit rules are configured to monitor kernel module operations.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditKernelModulesCheck(BaseCheck):
    """Check for audit rules monitoring kernel module load/unload operations."""

    id = "audit_kernel_modules"
    name = "Audit Kernel Module Load/Unload"
    description = (
        "Verifies that audit rules are configured to monitor kernel "
        "module loading and unloading operations including init_module, "
        "finit_module, delete_module, and related syscalls"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # Kernel module-related syscalls
    MODULE_SYSCALLS = ["init_module", "finit_module", "delete_module"]

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

    def _check_module_rules(self, rules: list[str]) -> dict:
        """Check for kernel module-related audit rules."""
        findings = {
            "init_module_monitored": False,
            "delete_module_monitored": False,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for init_module/finit_module syscalls
            if re.search(r"\binit_module\b|\bfinit_module\b", rule, re.IGNORECASE):
                findings["init_module_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            # Check for delete_module syscall
            if re.search(r"\bdelete_module\b", rule, re.IGNORECASE):
                findings["delete_module_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the kernel module audit check."""
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
                    "Configure audit rules to monitor kernel module operations:\n\n"
                    "1. Create /etc/audit/rules.d/modules.rules:\n\n"
                    "   # Monitor kernel module loading (64-bit)\n"
                    "   -a always,exit -F arch=b64 -S init_module -S finit_module -k modules\n\n"
                    "   # Monitor kernel module unloading (64-bit)\n"
                    "   -a always,exit -F arch=b64 -S delete_module -k modules\n\n"
                    "   # Monitor kernel module loading (32-bit)\n"
                    "   -a always,exit -F arch=b32 -S init_module -S finit_module -k modules\n\n"
                    "   # Monitor kernel module unloading (32-bit)\n"
                    "   -a always,exit -F arch=b32 -S delete_module -k modules\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep modules"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_module_rules(rules)
        details.update(findings)

        # Check for module monitoring
        missing = []
        if not findings["init_module_monitored"]:
            missing.append("init_module/finit_module")
        if not findings["delete_module_monitored"]:
            missing.append("delete_module")

        if missing:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Missing kernel module audit rules for: {', '.join(missing)}",
                remediation=(
                    f"Add kernel module audit rules to /etc/audit/rules.d/modules.rules:\n\n"
                    f"Missing: {', '.join(missing)}\n\n"
                    f"Add these rules:\n"
                    f"-a always,exit -F arch=b64 -S init_module -S finit_module -k modules\n"
                    f"-a always,exit -F arch=b64 -S delete_module -k modules\n"
                    f"-a always,exit -F arch=b32 -S init_module -S finit_module -k modules\n"
                    f"-a always,exit -F arch=b32 -S delete_module -k modules\n\n"
                    f"Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor kernel module load/unload operations",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
