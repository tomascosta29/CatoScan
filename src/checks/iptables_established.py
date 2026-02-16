"""
CIS Audit Check: iptables Outbound/Established Connections (3.6.4)

Ensures iptables has rules for outbound and established connections.
"""

import subprocess
import re

from src.core.check import BaseCheck, CheckResult, Severity


class IPTablesEstablishedCheck(BaseCheck):
    """Check if iptables has rules for established and outbound connections."""

    id = "iptables_established"
    name = "iptables Outbound/Established Connections"
    description = (
        "Verifies that iptables has rules allowing established connections "
        "and appropriate outbound connection rules"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _get_iptables_rules(self) -> dict:
        """Get iptables rules for all chains.

        Returns:
            Dictionary with rules
        """
        result = {
            "input_rules": [],
            "output_rules": [],
            "forward_rules": [],
            "iptables_output": None,
            "error": None,
        }

        try:
            proc = subprocess.run(
                ["iptables", "-L", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                result["iptables_output"] = proc.stdout
                
                current_chain = None
                for line in proc.stdout.split("\n"):
                    # Detect chain header
                    if line.startswith("Chain INPUT"):
                        current_chain = "INPUT"
                    elif line.startswith("Chain OUTPUT"):
                        current_chain = "OUTPUT"
                    elif line.startswith("Chain FORWARD"):
                        current_chain = "FORWARD"
                    elif line.startswith("Chain "):
                        current_chain = None
                    # Parse rules
                    elif current_chain and re.match(r'^\s*\d+', line):
                        if current_chain == "INPUT":
                            result["input_rules"].append(line.strip())
                        elif current_chain == "OUTPUT":
                            result["output_rules"].append(line.strip())
                        elif current_chain == "FORWARD":
                            result["forward_rules"].append(line.strip())
            else:
                result["error"] = proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["error"] = str(e)

        return result

    def _check_established_rules(self, rules: dict) -> dict:
        """Check if established connection rules are configured.

        Args:
            rules: Dictionary with iptables rules

        Returns:
            Dictionary with check results
        """
        result = {
            "input_established": False,
            "output_established": False,
            "output_new_accept": False,
            "input_details": [],
            "output_details": [],
        }

        # Check INPUT chain for ESTABLISHED,RELATED rule
        for rule in rules.get("input_rules", []):
            # Look for state module with ESTABLISHED,RELATED
            if ("state" in rule or "ctstate" in rule) and "ESTABLISHED" in rule and "ACCEPT" in rule:
                result["input_established"] = True
                result["input_details"].append(rule)

        # Check OUTPUT chain for rules
        for rule in rules.get("output_rules", []):
            # Look for state module with ESTABLISHED,RELATED
            if ("state" in rule or "ctstate" in rule) and "ESTABLISHED" in rule and "ACCEPT" in rule:
                result["output_established"] = True
                result["output_details"].append(rule)
            # Look for NEW state allowing outbound connections
            if ("state" in rule or "ctstate" in rule) and "NEW" in rule and "ACCEPT" in rule:
                result["output_new_accept"] = True

        return result

    def run(self) -> CheckResult:
        """Execute the iptables established connections check.

        Returns:
            CheckResult with the outcome of the check
        """
        rules = self._get_iptables_rules()

        # Check if iptables command failed
        if rules["error"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Failed to get iptables rules: {rules['error']}",
                remediation=(
                    "Ensure iptables is installed and accessible:\n"
                    "1. Install iptables: sudo dnf install iptables\n"
                    "2. Check permissions: sudo iptables -L"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"rules": rules},
            )

        established_check = self._check_established_rules(rules)

        details = {
            "rules": rules,
            "established_check": established_check,
        }

        input_est_ok = established_check["input_established"]
        output_est_ok = established_check["output_established"]

        if input_est_ok and output_est_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="iptables has established/related connection rules configured",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not input_est_ok:
            issues.append("No ESTABLISHED,RELATED ACCEPT rule in INPUT chain")
        if not output_est_ok:
            issues.append("No ESTABLISHED,RELATED ACCEPT rule in OUTPUT chain")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"iptables established connection issues: {'; '.join(issues)}",
            remediation=(
                "Configure iptables for established connections:\n"
                "1. Allow established connections on INPUT:\n"
                "   sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "   Or with newer iptables:\n"
                "   sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
                "2. Allow established connections on OUTPUT:\n"
                "   sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "3. Allow new outbound connections (if needed):\n"
                "   sudo iptables -A OUTPUT -m state --state NEW -j ACCEPT\n"
                "4. Save rules: sudo service iptables save\n"
                "   Or: sudo /usr/libexec/iptables/iptables.init save"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
