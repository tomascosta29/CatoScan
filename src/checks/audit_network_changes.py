"""
CIS Audit Check: Audit Network Environment Changes (4.4.9)

Checks if audit rules are configured to monitor network environment changes.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AuditNetworkChangesCheck(BaseCheck):
    """Check for audit rules monitoring network environment changes."""

    id = "audit_network_changes"
    name = "Audit Network Environment Changes"
    description = (
        "Verifies that audit rules are configured to monitor changes to "
        "network environment including hostname, network configuration, and DNS settings"
    )
    severity = Severity.HIGH
    requires_root = True

    AUDIT_RULES_FILE = "/etc/audit/audit.rules"
    AUDIT_RULES_D_DIR = "/etc/audit/rules.d"

    DEFAULT_NETWORK_CONFIG_PATHS = [
        "/etc/sysconfig/network",
        "/etc/NetworkManager",
        "/etc/netplan",
        "/etc/systemd/network",
    ]

    def _network_config_paths(self) -> list[str]:
        """Get platform-aware network configuration path patterns."""
        paths = self.platform_context.get_paths("network_config_paths")
        if paths:
            return paths
        return self.DEFAULT_NETWORK_CONFIG_PATHS

    def _normalize_watch_target(self, path_pattern: str) -> str:
        """Normalize glob path pattern to an audit watch target."""
        wildcard_indices = [
            idx
            for idx in [
                path_pattern.find("*"),
                path_pattern.find("?"),
                path_pattern.find("["),
            ]
            if idx != -1
        ]

        if not wildcard_indices:
            return path_pattern

        cut_index = min(wildcard_indices)
        prefix = path_pattern[:cut_index]

        if "/" in prefix:
            parent = prefix.rsplit("/", 1)[0]
            return f"{parent}/" if parent else "/"
        return prefix

    def _watch_targets(self) -> list[str]:
        """Get normalized watch targets for remediation guidance."""
        targets = [
            "/etc/hostname",
            "/etc/hosts",
            "/etc/resolv.conf",
        ]

        for path_pattern in self._network_config_paths():
            target = self._normalize_watch_target(path_pattern)
            if target and target not in targets:
                targets.append(target)

        return targets

    def _network_rule_regex(self) -> re.Pattern[str]:
        """Build regex for matching network config audit rules."""
        escaped_patterns: list[str] = []
        for path_pattern in self._network_config_paths():
            escaped = re.escape(path_pattern)
            escaped = escaped.replace(r"\*", ".*")
            escaped = escaped.replace(r"\?", ".")
            escaped_patterns.append(escaped)

        if not escaped_patterns:
            escaped_patterns = [re.escape(p) for p in self.DEFAULT_NETWORK_CONFIG_PATHS]

        return re.compile("|".join(escaped_patterns), re.IGNORECASE)

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

    def _check_network_rules(self, rules: list[str]) -> dict:
        """Check for network-related audit rules."""
        network_regex = self._network_rule_regex()
        findings = {
            "hostname_monitored": False,
            "hosts_monitored": False,
            "resolv_conf_monitored": False,
            "network_scripts_monitored": False,
            "sysctl_monitored": False,
            "hostname_syscalls": False,
            "matching_rules": [],
        }

        for rule in rules:
            if re.search(r"/etc/hostname", rule, re.IGNORECASE):
                findings["hostname_monitored"] = True
                findings["matching_rules"].append(rule)
            if re.search(r"/etc/hosts", rule, re.IGNORECASE):
                findings["hosts_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            if re.search(r"/etc/resolv\.conf", rule, re.IGNORECASE):
                findings["resolv_conf_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            if network_regex.search(rule):
                findings["network_scripts_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            if re.search(r"/etc/sysctl", rule, re.IGNORECASE):
                findings["sysctl_monitored"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)
            if re.search(r"sethostname|setdomainname", rule, re.IGNORECASE):
                findings["hostname_syscalls"] = True
                if rule not in findings["matching_rules"]:
                    findings["matching_rules"].append(rule)

        return findings

    def run(self) -> CheckResult:
        """Execute the network changes audit check."""
        details = {
            "audit_rules_file_exists": os.path.exists(self.AUDIT_RULES_FILE),
            "audit_rules_d_exists": os.path.isdir(self.AUDIT_RULES_D_DIR),
            "network_config_paths": self._network_config_paths(),
        }

        rules = self._collect_all_rules()
        details["total_rules"] = len(rules)

        if not rules:
            watch_lines = [
                f"   -w {target} -p wa -k system-locale"
                for target in self._watch_targets()
            ]
            joined_watch_lines = "\n".join(watch_lines)

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No audit rules are configured",
                remediation=(
                    "Configure audit rules to monitor network environment changes:\n\n"
                    "1. Create /etc/audit/rules.d/network.rules:\n\n"
                    "   # Monitor hostname changes\n"
                    "   -w /etc/hostname -p wa -k system-locale\n"
                    "   -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale\n\n"
                    "   # Monitor network configuration paths\n"
                    f"{joined_watch_lines}\n\n"
                    "2. Load rules: augenrules --load\n"
                    "3. Verify: auditctl -l | grep system-locale"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        findings = self._check_network_rules(rules)
        details.update(findings)

        # Check for essential network monitoring
        essential_checks = [
            ("hostname_monitored", "hostname monitoring"),
            ("hosts_monitored", "/etc/hosts monitoring"),
            ("resolv_conf_monitored", "DNS configuration monitoring"),
        ]

        missing = [desc for check, desc in essential_checks if not findings.get(check)]

        if missing:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Missing network environment audit rules: {', '.join(missing)}",
                remediation=(
                    f"Add missing audit rules to /etc/audit/rules.d/network.rules:\n\n"
                    f"Missing: {', '.join(missing)}\n\n"
                    f"Add these rules:\n"
                    f"-w /etc/hostname -p wa -k system-locale\n"
                    f"-w /etc/hosts -p wa -k system-locale\n"
                    f"-w /etc/resolv.conf -p wa -k system-locale\n\n"
                    f"Then reload: augenrules --load"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Audit rules are configured to monitor network environment changes",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
