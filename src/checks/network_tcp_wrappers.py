"""
CIS Audit Check: TCP Wrappers Configuration

Checks if TCP wrappers is configured with reasonable restrictions
in /etc/hosts.allow and /etc/hosts.deny.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class TCPWrappersCheck(BaseCheck):
    """Check for TCP wrappers configuration."""

    id = "network_tcp_wrappers"
    name = "TCP Wrappers Configuration"
    description = (
        "Verifies that TCP wrappers is configured with reasonable "
        "restrictions in /etc/hosts.allow and /etc/hosts.deny"
    )
    severity = Severity.MEDIUM
    requires_root = True

    HOSTS_ALLOW = "/etc/hosts.allow"
    HOSTS_DENY = "/etc/hosts.deny"

    # Services that should typically be restricted
    SENSITIVE_SERVICES = [
        "sshd", "ssh", "telnet", "ftp", "vsftpd", "proftpd",
        "rlogin", "rsh", "rexec", "rcp",
    ]

    def _parse_hosts_file(self, filepath: str) -> dict:
        """Parse a hosts.allow or hosts.deny file.

        Args:
            filepath: Path to the file to parse

        Returns:
            Dictionary with parsed rules and metadata
        """
        result = {
            "exists": False,
            "readable": False,
            "rules": [],
            "comments": [],
            "all_deny": False,
            "all_allow": False,
            "sensitive_services": [],
            "errors": [],
        }

        if not os.path.exists(filepath):
            result["errors"].append(f"File does not exist: {filepath}")
            return result

        result["exists"] = True

        try:
            with open(filepath, "r") as f:
                content = f.read()
            result["readable"] = True

            for line_num, line in enumerate(content.split("\n"), 1):
                original_line = line
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Collect comments
                if line.startswith("#"):
                    result["comments"].append({
                        "line": line_num,
                        "content": line[1:].strip(),
                    })
                    continue

                # Parse rule (format: daemon_list : client_list [: shell_command])
                # Handle line continuations (backslash at end)
                if line.endswith("\\"):
                    line = line[:-1].strip()

                # Split by colon
                parts = line.split(":")
                if len(parts) >= 2:
                    daemons = parts[0].strip()
                    clients = parts[1].strip()

                    rule = {
                        "line": line_num,
                        "daemons": daemons,
                        "clients": clients,
                        "raw": original_line.strip(),
                    }

                    if len(parts) >= 3:
                        rule["command"] = parts[2].strip()

                    result["rules"].append(rule)

                    # Check for ALL keyword
                    if daemons.upper() == "ALL":
                        if "ALL" in clients.upper() or "ALL" in clients.upper():
                            if "deny" in filepath.lower() or "deny" in filepath.lower():
                                result["all_deny"] = True
                            else:
                                result["all_allow"] = True

                    # Check for sensitive services
                    for service in self.SENSITIVE_SERVICES:
                        if service.lower() in daemons.lower():
                            result["sensitive_services"].append({
                                "service": service,
                                "line": line_num,
                                "rule": rule,
                            })

        except (IOError, OSError) as e:
            result["errors"].append(f"Error reading {filepath}: {str(e)}")
            result["readable"] = False

        return result

    def _check_tcp_wrappers_support(self) -> dict:
        """Check if TCP wrappers library is available on the system.

        Returns:
            Dictionary with library findings
        """
        result = {
            "libwrap_available": False,
            "tcpd_available": False,
            "libraries": [],
        }

        # Check for libwrap.so
        lib_paths = [
            "/lib/libwrap.so",
            "/lib64/libwrap.so",
            "/usr/lib/libwrap.so",
            "/usr/lib64/libwrap.so",
        ]

        for path in lib_paths:
            if os.path.exists(path) or os.path.exists(f"{path}.0"):
                result["libwrap_available"] = True
                result["libraries"].append(path)

        # Check for tcpd command
        if os.path.exists("/usr/sbin/tcpd"):
            result["tcpd_available"] = True

        return result

    def _evaluate_configuration(self, allow_config: dict, deny_config: dict) -> tuple[bool, list[str], str]:
        """Evaluate the TCP wrappers configuration.

        Args:
            allow_config: Parsed hosts.allow configuration
            deny_config: Parsed hosts.deny configuration

        Returns:
            Tuple of (is_secure, issues_list, recommendation)
        """
        issues = []
        recommendations = []

        # Check if files exist
        if not allow_config["exists"] and not deny_config["exists"]:
            issues.append("Neither /etc/hosts.allow nor /etc/hosts.deny exists")
            recommendations.append("Create /etc/hosts.deny with 'ALL: ALL' to deny all connections by default")
            recommendations.append("Then create /etc/hosts.allow for specific allowed services")
            return False, issues, "\n".join(recommendations)

        # Check hosts.deny for default deny
        if deny_config["exists"]:
            if not deny_config["rules"] and not deny_config["all_deny"]:
                # File exists but may be empty or only comments
                issues.append("/etc/hosts.deny exists but has no deny rules")
                recommendations.append("Add 'ALL: ALL' to /etc/hosts.deny to deny all connections by default")
        else:
            issues.append("/etc/hosts.deny does not exist")
            recommendations.append("Create /etc/hosts.deny with 'ALL: ALL' to deny all connections by default")

        # Check hosts.allow for specific allows
        if allow_config["exists"]:
            if not allow_config["rules"]:
                issues.append("/etc/hosts.allow exists but has no allow rules")
                recommendations.append("Add specific service allow rules to /etc/hosts.allow (e.g., 'sshd: 192.168.1.0/255.255.255.0')")
        else:
            issues.append("/etc/hosts.allow does not exist")
            recommendations.append("Create /etc/hosts.allow to explicitly allow required services")

        # Check for overly permissive rules
        for rule in allow_config.get("rules", []):
            if rule["daemons"].upper() == "ALL" and rule["clients"].upper() == "ALL":
                issues.append("/etc/hosts.allow has overly permissive rule: ALL: ALL")
                recommendations.append("Remove or restrict the 'ALL: ALL' rule in /etc/hosts.allow")

        # Check for specific service restrictions
        sensitive_in_allow = allow_config.get("sensitive_services", [])
        if sensitive_in_allow:
            for svc in sensitive_in_allow:
                if svc["service"] in ["telnet", "ftp", "rlogin", "rsh", "rexec"]:
                    issues.append(f"Potentially insecure service '{svc['service']}' is allowed in /etc/hosts.allow")
                    recommendations.append(f"Review if {svc['service']} access is necessary - consider using secure alternatives")

        # Build recommendation string
        if not recommendations:
            recommendation = ""
        else:
            recommendation = "TCP Wrappers Configuration:\n" + "\n".join([f"{i+1}. {r}" for i, r in enumerate(recommendations)])

        return len(issues) == 0, issues, recommendation

    def run(self) -> CheckResult:
        """Execute the TCP wrappers check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "libwrap": {},
            "hosts_allow": {},
            "hosts_deny": {},
            "is_secure": False,
            "issues": [],
        }

        # Check TCP wrappers library support
        libwrap_info = self._check_tcp_wrappers_support()
        details["libwrap"] = libwrap_info

        # Parse hosts.allow
        allow_config = self._parse_hosts_file(self.HOSTS_ALLOW)
        details["hosts_allow"] = allow_config

        # Parse hosts.deny
        deny_config = self._parse_hosts_file(self.HOSTS_DENY)
        details["hosts_deny"] = deny_config

        # Evaluate configuration
        is_secure, issues, recommendation = self._evaluate_configuration(allow_config, deny_config)
        details["is_secure"] = is_secure
        details["issues"] = issues

        # Build result
        if not allow_config["exists"] and not deny_config["exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="TCP wrappers configuration files do not exist",
                remediation=(
                    "Configure TCP wrappers for access control:\n"
                    "1. Create /etc/hosts.deny with:\n"
                    "   ALL: ALL\n"
                    "2. Create /etc/hosts.allow with specific allowed services:\n"
                    "   sshd: 192.168.1.\n"
                    "   # Or for specific IPs:\n"
                    "   sshd: 10.0.0.1, 10.0.0.2\n"
                    "3. Verify configuration with: tcpdchk -v"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if not is_secure:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"TCP wrappers configuration has issues: {'; '.join(issues)}",
                remediation=recommendation or (
                    "Review and tighten TCP wrappers configuration:\n"
                    "1. Ensure /etc/hosts.deny contains 'ALL: ALL'\n"
                    "2. Add specific allow rules to /etc/hosts.allow\n"
                    "3. Avoid using 'ALL: ALL' in hosts.allow\n"
                    "4. Verify with: tcpdchk -v"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Configuration looks good
        allow_rules_count = len(allow_config.get("rules", []))
        deny_rules_count = len(deny_config.get("rules", []))

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"TCP wrappers is properly configured ({allow_rules_count} allow rules, {deny_rules_count} deny rules)",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
