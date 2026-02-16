"""
CIS Audit Check: Audit Rules Configuration

Checks if audit rules are configured to monitor security-relevant events.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditRulesCheck(BaseCheck):
    """Check for audit rules configuration."""

    id = "logging_audit_rules"
    name = "Audit Rules Configuration"
    description = (
        "Verifies that audit rules are configured to monitor "
        "security-relevant events such as user/group modifications, "
        "authentication events, and privilege escalation"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    # Categories of audit rules to check
    RULE_CATEGORIES = {
        "user_modification": {
            "description": "User account modification",
            "patterns": [
                r"/etc/passwd",
                r"/etc/shadow",
                r"/etc/group",
                r"/etc/gshadow",
                r"/etc/security/opasswd",
            ],
        },
        "authentication": {
            "description": "Authentication events",
            "patterns": [
                r"/etc/pam.d",
                r"/var/log/lastlog",
                r"/var/run/faillock",
                r"pam_tally",
                r"pam_faillock",
            ],
        },
        "privilege_escalation": {
            "description": "Privilege escalation (sudo/su)",
            "patterns": [
                r"/etc/sudoers",
                r"/etc/sudoers.d",
                r"/bin/su",
                r"/usr/bin/sudo",
                r"setuid",
            ],
        },
        "login_logout": {
            "description": "Login/logout events",
            "patterns": [
                r"USER_LOGIN",
                r"USER_LOGOUT",
                r"USER_START",
                r"USER_END",
            ],
        },
        "permission_changes": {
            "description": "Permission/ownership changes",
            "patterns": [
                r"chmod",
                r"chown",
                r"fchmod",
                r"fchown",
                r"lchown",
            ],
        },
        "mount_changes": {
            "description": "Mount/unmount operations",
            "patterns": [
                r"mount",
                r"umount",
                r"MOUNT",
                r"UNMOUNT",
            ],
        },
    }

    def _parse_rules_from_file(self, file_path: str) -> list[str]:
        """Parse audit rules from a file.

        Args:
            file_path: Path to the audit rules file

        Returns:
            List of rule lines (excluding comments and empty lines)
        """
        rules = []

        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue
                    # Skip control rules (delete, exclude, etc.)
                    if line.startswith("-"):
                        continue
                    rules.append(line)
        except (IOError, OSError):
            pass

        return rules

    def _collect_all_rules(self) -> list[str]:
        """Collect all audit rules from all sources.

        Returns:
            List of all active audit rules
        """
        all_rules = []

        # Check rules.d directory first (modern systems)
        if os.path.isdir(self.AUDIT_RULES_D_DIR):
            try:
                # Sort to ensure consistent ordering
                for rules_file in sorted(Path(self.AUDIT_RULES_D_DIR).glob("*.rules")):
                    all_rules.extend(self._parse_rules_from_file(str(rules_file)))
            except (IOError, OSError):
                pass

        # Also check the main audit.rules file
        if os.path.exists(self.AUDIT_RULES_FILE):
            all_rules.extend(self._parse_rules_from_file(self.AUDIT_RULES_FILE))

        return all_rules

    def _analyze_rules(self, rules: list[str]) -> dict:
        """Analyze audit rules and categorize them.

        Args:
            rules: List of audit rules

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            "total_rules": len(rules),
            "categories_found": {},
            "rules_by_category": {},
            "sample_rules": rules[:10] if rules else [],
        }

        rules_text = "\n".join(rules)

        for category, info in self.RULE_CATEGORIES.items():
            found = False
            matching_rules = []

            for pattern in info["patterns"]:
                for rule in rules:
                    if re.search(pattern, rule, re.IGNORECASE):
                        found = True
                        if rule not in matching_rules:
                            matching_rules.append(rule)

            if found:
                analysis["categories_found"][category] = info["description"]
                analysis["rules_by_category"][category] = matching_rules[:5]  # Limit output

        return analysis

    def run(self) -> CheckResult:
        """Execute the audit rules check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "audit_rules_file_exists": os.path.exists(self.AUDIT_RULES_FILE),
            "audit_rules_d_exists": os.path.isdir(self.AUDIT_RULES_D_DIR),
            "rules_analysis": {},
        }

        # Collect all rules
        rules = self._collect_all_rules()
        analysis = self._analyze_rules(rules)
        details["rules_analysis"] = analysis

        # Check if any rules are configured
        if not rules:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules are configured",
                remediation=(
                    "Configure audit rules to monitor security-relevant events:\n\n"
                    "1. Create audit rules in /etc/audit/rules.d/audit.rules:\n\n"
                    "   # Monitor user/group modifications\n"
                    "   -w /etc/passwd -p wa -k identity\n"
                    "   -w /etc/group -p wa -k identity\n"
                    "   -w /etc/shadow -p wa -k identity\n"
                    "   -w /etc/gshadow -p wa -k identity\n\n"
                    "   # Monitor authentication configuration\n"
                    "   -w /etc/pam.d/ -p wa -k auth-config\n\n"
                    "   # Monitor sudo configuration\n"
                    "   -w /etc/sudoers -p wa -k sudoers\n"
                    "   -w /etc/sudoers.d/ -p wa -k sudoers\n\n"
                    "   # Monitor privilege escalation\n"
                    "   -a always,exit -F arch=b64 -S setuid -S setgid -S setreuid "
                    "-S setregid -k privilege_escalation\n\n"
                    "   # Monitor login/logout events\n"
                    "   -w /var/log/lastlog -p wa -k logins\n"
                    "   -w /var/run/faillock -p wa -k logins\n\n"
                    "2. Load the rules: augenrules --load\n"
                    "3. Verify rules: auditctl -l\n\n"
                    "See CIS Benchmark for Fedora 43 for complete audit rules recommendations."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check for basic security rule coverage
        categories_found = analysis["categories_found"]
        essential_categories = ["user_modification", "authentication"]
        missing_essential = [
            cat for cat in essential_categories if cat not in categories_found
        ]

        if missing_essential:
            missing_names = [
                self.RULE_CATEGORIES[cat]["description"] for cat in missing_essential
            ]
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Audit rules exist but missing essential categories: "
                    f"{', '.join(missing_names)}"
                ),
                remediation=(
                    f"Add missing audit rule categories:\n\n"
                    f"Missing: {', '.join(missing_names)}\n\n"
                    f"Add to /etc/audit/rules.d/audit.rules:\n\n"
                    f"# User account modifications\n"
                    f"-w /etc/passwd -p wa -k identity\n"
                    f"-w /etc/shadow -p wa -k identity\n"
                    f"-w /etc/group -p wa -k identity\n"
                    f"-w /etc/gshadow -p wa -k identity\n\n"
                    f"# Authentication configuration\n"
                    f"-w /etc/pam.d/ -p wa -k auth-config\n\n"
                    f"Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if we have a reasonable number of rules
        if analysis["total_rules"] < 5:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Only {analysis['total_rules']} audit rules configured (minimum recommended: 5)",
                remediation=(
                    "Add more comprehensive audit rules:\n"
                    "1. Review CIS Benchmark for recommended audit rules\n"
                    "2. Add rules for user modifications, authentication, sudo, etc.\n"
                    "3. Reload rules: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"Audit rules are configured ({analysis['total_rules']} rules, "
                f"{len(categories_found)} categories: {', '.join(categories_found.values())})"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
