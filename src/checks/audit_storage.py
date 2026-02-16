"""
CIS Audit Check: Audit Log Storage Size (4.4.2.1)

Checks if audit log storage size is configured appropriately.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditStorageCheck(BaseCheck):
    """Check for audit log storage size configuration."""

    id = "audit_storage"
    name = "Audit Log Storage Size"
    description = (
        "Verifies that audit log storage size is configured to prevent "
        "log loss due to insufficient disk space"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDITD_CONF = "/etc/audit/auditd.conf"
    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # Recommended minimum log file size in MB
    MIN_LOG_FILE_SIZE = 8  # MB
    MAX_LOG_FILE_SIZE = 50  # MB (to prevent files from becoming too large)

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

    def _check_auditd_conf(self) -> dict:
        """Check auditd.conf for log file size settings."""
        findings = {
            "config_exists": os.path.exists(self.AUDITD_CONF),
            "max_log_file_set": False,
            "max_log_file_value": None,
            "num_logs_set": False,
            "num_logs_value": None,
        }

        if os.path.exists(self.AUDITD_CONF):
            try:
                with open(self.AUDITD_CONF, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("max_log_file"):
                            match = re.search(r"max_log_file\s*=\s*(\d+)", line)
                            if match:
                                findings["max_log_file_set"] = True
                                findings["max_log_file_value"] = int(match.group(1))
                        elif line.startswith("num_logs"):
                            match = re.search(r"num_logs\s*=\s*(\d+)", line)
                            if match:
                                findings["num_logs_set"] = True
                                findings["num_logs_value"] = int(match.group(1))
            except (IOError, OSError):
                pass

        return findings

    def run(self) -> CheckResult:
        """Execute the audit log storage size check."""
        conf_findings = self._check_auditd_conf()

        details = {
            "auditd_conf_exists": conf_findings["config_exists"],
            "max_log_file": conf_findings["max_log_file_value"],
            "num_logs": conf_findings["num_logs_value"],
        }

        if not conf_findings["config_exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="auditd.conf not found",
                remediation=(
                    "Install and configure auditd:\n"
                    "dnf install audit\n\n"
                    "Then configure /etc/audit/auditd.conf with appropriate log settings."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        remediation_steps = []

        # Check max_log_file setting
        if not conf_findings["max_log_file_set"]:
            issues.append("max_log_file not configured")
            remediation_steps.append(
                "Set max_log_file in /etc/audit/auditd.conf:\n"
                f"max_log_file = {self.MIN_LOG_FILE_SIZE}"
            )
        elif conf_findings["max_log_file_value"] < self.MIN_LOG_FILE_SIZE:
            issues.append(
                f"max_log_file ({conf_findings['max_log_file_value']} MB) is less than "
                f"recommended ({self.MIN_LOG_FILE_SIZE} MB)"
            )
            remediation_steps.append(
                f"Increase max_log_file in /etc/audit/auditd.conf:\n"
                f"max_log_file = {self.MIN_LOG_FILE_SIZE}"
            )

        # Check num_logs setting
        if not conf_findings["num_logs_set"]:
            issues.append("num_logs not configured")
            remediation_steps.append(
                "Set num_logs in /etc/audit/auditd.conf:\n"
                "num_logs = 5"
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Audit log storage issues: {'; '.join(issues)}",
                remediation="\n\n".join(remediation_steps),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"Audit log storage properly configured "
                f"(max_log_file={conf_findings['max_log_file_value']}MB, "
                f"num_logs={conf_findings['num_logs_value']})"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
