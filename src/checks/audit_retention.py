"""
CIS Audit Check: Audit Log Retention (4.4.2.2-4.4.2.3)

Checks if audit log retention and full action are configured appropriately.
"""

import os
import re

from src.core.check import BaseCheck, CheckResult, Severity


class AuditRetentionCheck(BaseCheck):
    """Check for audit log retention and full action configuration."""

    id = "audit_retention"
    name = "Audit Log Retention and Full Action"
    description = (
        "Verifies that audit log retention settings and actions when "
        "the audit log is full are configured to prevent log loss and "
        "ensure proper handling of audit storage issues"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDITD_CONF = "/etc/audit/auditd.conf"

    # Valid admin_space_left_actions
    VALID_ADMIN_ACTIONS = ["email", "exec", "halt", "ignore", "rotate", "suspend", "syslog", "single", "terminate"]
    # Valid space_left_actions
    VALID_SPACE_ACTIONS = ["email", "exec", "halt", "ignore", "rotate", "suspend", "syslog", "single", "terminate"]
    # Valid disk_full_actions
    VALID_FULL_ACTIONS = ["email", "exec", "halt", "ignore", "rotate", "suspend", "syslog", "single", "terminate"]
    # Valid disk_error_actions
    VALID_ERROR_ACTIONS = ["email", "exec", "halt", "ignore", "rotate", "suspend", "syslog", "single", "terminate"]

    def _check_auditd_conf(self) -> dict:
        """Check auditd.conf for retention settings."""
        findings = {
            "config_exists": os.path.exists(self.AUDITD_CONF),
            "admin_space_left_set": False,
            "admin_space_left_value": None,
            "admin_space_left_action_set": False,
            "admin_space_left_action_value": None,
            "space_left_set": False,
            "space_left_value": None,
            "space_left_action_set": False,
            "space_left_action_value": None,
            "disk_full_action_set": False,
            "disk_full_action_value": None,
            "disk_error_action_set": False,
            "disk_error_action_value": None,
            "max_log_file_action_set": False,
            "max_log_file_action_value": None,
        }

        if os.path.exists(self.AUDITD_CONF):
            try:
                with open(self.AUDITD_CONF, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("admin_space_left") and not line.startswith("admin_space_left_action"):
                            match = re.search(r"admin_space_left\s*=\s*(\d+)", line)
                            if match:
                                findings["admin_space_left_set"] = True
                                findings["admin_space_left_value"] = int(match.group(1))
                        elif line.startswith("admin_space_left_action"):
                            match = re.search(r"admin_space_left_action\s*=\s*(\S+)", line)
                            if match:
                                findings["admin_space_left_action_set"] = True
                                findings["admin_space_left_action_value"] = match.group(1)
                        elif line.startswith("space_left") and not line.startswith("space_left_action"):
                            match = re.search(r"space_left\s*=\s*(\d+)", line)
                            if match:
                                findings["space_left_set"] = True
                                findings["space_left_value"] = int(match.group(1))
                        elif line.startswith("space_left_action"):
                            match = re.search(r"space_left_action\s*=\s*(\S+)", line)
                            if match:
                                findings["space_left_action_set"] = True
                                findings["space_left_action_value"] = match.group(1)
                        elif line.startswith("disk_full_action"):
                            match = re.search(r"disk_full_action\s*=\s*(\S+)", line)
                            if match:
                                findings["disk_full_action_set"] = True
                                findings["disk_full_action_value"] = match.group(1)
                        elif line.startswith("disk_error_action"):
                            match = re.search(r"disk_error_action\s*=\s*(\S+)", line)
                            if match:
                                findings["disk_error_action_set"] = True
                                findings["disk_error_action_value"] = match.group(1)
                        elif line.startswith("max_log_file_action"):
                            match = re.search(r"max_log_file_action\s*=\s*(\S+)", line)
                            if match:
                                findings["max_log_file_action_set"] = True
                                findings["max_log_file_action_value"] = match.group(1)
            except (IOError, OSError):
                pass

        return findings

    def run(self) -> CheckResult:
        """Execute the audit log retention check."""
        conf_findings = self._check_auditd_conf()

        details = {
            "auditd_conf_exists": conf_findings["config_exists"],
            "admin_space_left": conf_findings["admin_space_left_value"],
            "admin_space_left_action": conf_findings["admin_space_left_action_value"],
            "space_left": conf_findings["space_left_value"],
            "space_left_action": conf_findings["space_left_action_value"],
            "disk_full_action": conf_findings["disk_full_action_value"],
            "disk_error_action": conf_findings["disk_error_action_value"],
            "max_log_file_action": conf_findings["max_log_file_action_value"],
        }

        if not conf_findings["config_exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="auditd.conf not found",
                remediation=(
                    "Install and configure auditd:\n"
                    "dnf install audit\n\n"
                    "Then configure /etc/audit/auditd.conf with appropriate retention settings."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        remediation_steps = []

        # Check admin_space_left (should be set to alert when disk is nearly full)
        if not conf_findings["admin_space_left_set"]:
            issues.append("admin_space_left not configured")
            remediation_steps.append(
                "Set admin_space_left in /etc/audit/auditd.conf:\n"
                "admin_space_left = 50  # MB"
            )

        # Check admin_space_left_action (should be halt or single for security)
        if not conf_findings["admin_space_left_action_set"]:
            issues.append("admin_space_left_action not configured")
            remediation_steps.append(
                "Set admin_space_left_action in /etc/audit/auditd.conf:\n"
                "admin_space_left_action = halt  # or 'single' for maintenance mode"
            )
        elif conf_findings["admin_space_left_action_value"] not in ["halt", "single", "suspend"]:
            issues.append(
                f"admin_space_left_action ({conf_findings['admin_space_left_action_value']}) "
                "should be more restrictive (halt, single, or suspend)"
            )

        # Check space_left (early warning)
        if not conf_findings["space_left_set"]:
            issues.append("space_left not configured")
            remediation_steps.append(
                "Set space_left in /etc/audit/auditd.conf:\n"
                "space_left = 100  # MB (should be > admin_space_left)"
            )

        # Check space_left_action
        if not conf_findings["space_left_action_set"]:
            issues.append("space_left_action not configured")
            remediation_steps.append(
                "Set space_left_action in /etc/audit/auditd.conf:\n"
                "space_left_action = email  # or 'syslog'"
            )

        # Check disk_full_action
        if not conf_findings["disk_full_action_set"]:
            issues.append("disk_full_action not configured")
            remediation_steps.append(
                "Set disk_full_action in /etc/audit/auditd.conf:\n"
                "disk_full_action = halt  # or 'single' or 'suspend'"
            )
        elif conf_findings["disk_full_action_value"] not in ["halt", "single", "suspend"]:
            issues.append(
                f"disk_full_action ({conf_findings['disk_full_action_value']}) "
                "should be more restrictive (halt, single, or suspend)"
            )

        # Check disk_error_action
        if not conf_findings["disk_error_action_set"]:
            issues.append("disk_error_action not configured")
            remediation_steps.append(
                "Set disk_error_action in /etc/audit/auditd.conf:\n"
                "disk_error_action = syslog  # or 'single' or 'suspend'"
            )

        # Check max_log_file_action
        if not conf_findings["max_log_file_action_set"]:
            issues.append("max_log_file_action not configured")
            remediation_steps.append(
                "Set max_log_file_action in /etc/audit/auditd.conf:\n"
                "max_log_file_action = rotate  # or 'keep_logs'"
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Audit log retention issues: {'; '.join(issues)}",
                remediation="\n\n".join(remediation_steps) if remediation_steps else "Review and update /etc/audit/auditd.conf",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit log retention and full action settings are properly configured",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
