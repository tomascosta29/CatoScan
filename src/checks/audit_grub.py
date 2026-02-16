"""
CIS Audit Check: Audit GRUB Configuration (4.4.1.3-4.4.1.4)

Checks if audit rules are configured for early boot auditing and backlog settings.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditGrubCheck(BaseCheck):
    """Check for audit early boot and backlog configuration."""

    id = "audit_grub"
    name = "Audit Early Boot and Backlog Configuration"
    description = (
        "Verifies that audit is configured to start early in the boot process "
        "and that the audit backlog is set to a sufficient size to prevent "
        "event loss during high-volume periods"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    def _get_grub_cmdline_path(self) -> str:
        """Get platform-aware GRUB default config path."""
        paths = self.platform_context.get_paths("grub_default_config")
        if paths:
            return paths[0]
        return "/etc/default/grub"

    def _preferred_grub_output_path(self) -> str:
        """Get best GRUB output path for mkconfig command."""
        paths = self.platform_context.get_paths("grub_cfg")
        for path in paths:
            if os.path.exists(path):
                return path
        if paths:
            return paths[0]
        return "/boot/grub2/grub.cfg"

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

    def _check_backlog_settings(self, rules: list[str]) -> dict:
        """Check for audit backlog configuration."""
        findings = {
            "backlog_limit_set": False,
            "backlog_limit_value": None,
            "backlog_wait_time_set": False,
            "backlog_wait_time_value": None,
            "matching_rules": [],
        }

        for rule in rules:
            # Check for backlog limit (-b)
            match = re.search(r"^-b\s+(\d+)", rule)
            if match:
                findings["backlog_limit_set"] = True
                findings["backlog_limit_value"] = int(match.group(1))
                findings["matching_rules"].append(rule)
            # Check for backlog wait time (--backlog_wait_time)
            match = re.search(r"--backlog_wait_time\s+(\d+)", rule)
            if match:
                findings["backlog_wait_time_set"] = True
                findings["backlog_wait_time_value"] = int(match.group(1))
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def _check_grub_audit(self) -> dict:
        """Check if audit=1 is set in GRUB configuration."""
        grub_cmdline = self._get_grub_cmdline_path()
        findings = {
            "grub_file": grub_cmdline,
            "grub_file_exists": os.path.exists(grub_cmdline),
            "audit_in_grub": False,
            "audit_line": None,
        }

        if os.path.exists(grub_cmdline):
            try:
                with open(grub_cmdline, "r") as f:
                    for line in f:
                        if line.startswith("GRUB_CMDLINE_LINUX"):
                            if "audit=1" in line or "audit_backlog_limit" in line:
                                findings["audit_in_grub"] = True
                                findings["audit_line"] = line.strip()
                                break
            except (IOError, OSError):
                pass

        return findings

    def run(self) -> CheckResult:
        """Execute the audit GRUB configuration check."""
        rules = self._collect_all_rules()
        backlog_findings = self._check_backlog_settings(rules)
        grub_findings = self._check_grub_audit()

        details = {
            "audit_rules_file_exists": os.path.exists(self.AUDIT_RULES_FILE),
            "audit_rules_d_exists": os.path.isdir(self.AUDIT_RULES_D_DIR),
            "grub_file_exists": grub_findings["grub_file_exists"],
            "grub_file": grub_findings.get("grub_file"),
            "backlog_settings": backlog_findings,
            "grub_settings": grub_findings,
            "total_rules": len(rules),
        }

        issues = []
        remediation_steps = []

        # Check backlog limit
        if not backlog_findings["backlog_limit_set"]:
            issues.append("Audit backlog limit not configured")
            remediation_steps.append(
                "Add to /etc/audit/rules.d/audit.rules:\n"
                "-b 8192  # Set backlog buffer size"
            )
        elif backlog_findings["backlog_limit_value"] and backlog_findings["backlog_limit_value"] < 8192:
            issues.append(f"Audit backlog limit ({backlog_findings['backlog_limit_value']}) is less than recommended (8192)")
            remediation_steps.append(
                "Increase backlog limit in /etc/audit/rules.d/audit.rules:\n"
                "-b 8192"
            )

        # Check GRUB audit setting
        if not grub_findings["audit_in_grub"]:
            grub_cmdline = self._get_grub_cmdline_path()
            mkconfig_cmd = self._platform_grub_mkconfig_command(self._preferred_grub_output_path())
            issues.append("Early boot audit not enabled in GRUB")
            remediation_steps.append(
                f"Add to {grub_cmdline} in GRUB_CMDLINE_LINUX:\n"
                "audit=1 audit_backlog_limit=8192\n"
                f"Then run: {mkconfig_cmd}"
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Audit boot configuration issues: {'; '.join(issues)}",
                remediation="\n\n".join(remediation_steps),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit early boot and backlog configuration is properly set",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
