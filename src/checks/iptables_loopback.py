"""
CIS Audit Check: iptables Loopback Traffic Configured (3.6.3)

Ensures iptables has rules configured for loopback traffic.
"""

import subprocess
import re

from src.core.check import BaseCheck, CheckResult, Severity


class IPTablesLoopbackCheck(BaseCheck):
    """Check if iptables has loopback traffic rules configured."""

    id = "iptables_loopback"
    name = "iptables Loopback Traffic Configured"
    description = (
        "Verifies that iptables has rules to allow loopback traffic (lo interface) "
        "and drop packets claiming to be from loopback on other interfaces"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _get_iptables_rules(self) -> dict:
        """Get iptables rules for INPUT and OUTPUT chains.

        Returns:
            Dictionary with rules
        """
        result = {
            "input_rules": [],
            "output_rules": [],
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
                    elif line.startswith("Chain "):
                        current_chain = None
                    # Parse rules (lines starting with a number or space+number)
                    elif current_chain and re.match(r'^\s*\d+', line):
                        if current_chain == "INPUT":
                            result["input_rules"].append(line.strip())
                        elif current_chain == "OUTPUT":
                            result["output_rules"].append(line.strip())
            else:
                result["error"] = proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["error"] = str(e)

        return result

    def _check_loopback_rules(self, rules: dict) -> dict:
        """Check if loopback rules are properly configured.

        Args:
            rules: Dictionary with input and output rules

        Returns:
            Dictionary with check results
        """
        result = {
            "input_lo_accept": False,
            "output_lo_accept": False,
            "input_spoof_drop": False,
            "input_lo_details": [],
            "output_lo_details": [],
            "spoof_details": [],
        }

        # Check INPUT chain for lo ACCEPT rules
        for rule in rules.get("input_rules", []):
            # Look for ACCEPT rules on lo interface
            if "lo" in rule and "ACCEPT" in rule:
                result["input_lo_accept"] = True
                result["input_lo_details"].append(rule)
            # Look for DROP rules for 127.0.0.0/8 on non-lo interfaces (spoof protection)
            if ("127.0.0.0/8" in rule or "127.0.0.1" in rule) and "DROP" in rule and "lo" not in rule:
                result["input_spoof_drop"] = True
                result["spoof_details"].append(rule)

        # Check OUTPUT chain for lo ACCEPT rules
        for rule in rules.get("output_rules", []):
            if "lo" in rule and "ACCEPT" in rule:
                result["output_lo_accept"] = True
                result["output_lo_details"].append(rule)

        return result

    def run(self) -> CheckResult:
        """Execute the iptables loopback check.

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

        loopback_check = self._check_loopback_rules(rules)

        details = {
            "rules": rules,
            "loopback_check": loopback_check,
        }

        input_lo_ok = loopback_check["input_lo_accept"]
        output_lo_ok = loopback_check["output_lo_accept"]
        spoof_ok = loopback_check["input_spoof_drop"]

        if input_lo_ok and output_lo_ok and spoof_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="iptables has proper loopback traffic rules configured",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not input_lo_ok:
            issues.append("No ACCEPT rule for loopback interface in INPUT chain")
        if not output_lo_ok:
            issues.append("No ACCEPT rule for loopback interface in OUTPUT chain")
        if not spoof_ok:
            issues.append("No DROP rule for loopback spoofing attempts")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"iptables loopback configuration issues: {'; '.join(issues)}",
            remediation=(
                "Configure iptables loopback rules:\n"
                "1. Allow loopback traffic on INPUT:\n"
                "   sudo iptables -A INPUT -i lo -j ACCEPT\n"
                "2. Allow loopback traffic on OUTPUT:\n"
                "   sudo iptables -A OUTPUT -o lo -j ACCEPT\n"
                "3. Drop spoofed loopback traffic:\n"
                "   sudo iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP\n"
                "4. Save rules: sudo service iptables save\n"
                "   Or: sudo /usr/libexec/iptables/iptables.init save"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
