"""
CIS Audit Check: iptables Default Deny Policy (3.6.2)

Ensures iptables has a default deny firewall policy.
"""

import subprocess
import re

from src.core.check import BaseCheck, CheckResult, Severity


class IPTablesDefaultDenyCheck(BaseCheck):
    """Check if iptables has default deny policy."""

    id = "iptables_default_deny"
    name = "iptables Default Deny Policy"
    description = (
        "Verifies that iptables has a default deny policy for INPUT, OUTPUT, "
        "and FORWARD chains"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _get_iptables_policy(self) -> dict:
        """Get iptables chain policies.

        Returns:
            Dictionary with chain policies
        """
        result = {
            "input_policy": None,
            "output_policy": None,
            "forward_policy": None,
            "iptables_output": None,
            "error": None,
        }

        try:
            proc = subprocess.run(
                ["iptables", "-L"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                result["iptables_output"] = proc.stdout
                
                # Parse chain policies
                for line in proc.stdout.split("\n"):
                    # Match lines like: Chain INPUT (policy ACCEPT)
                    match = re.search(r'Chain\s+(\w+)\s+\(policy\s+(\w+)\)', line)
                    if match:
                        chain_name = match.group(1).upper()
                        policy = match.group(2).upper()
                        if chain_name == "INPUT":
                            result["input_policy"] = policy
                        elif chain_name == "OUTPUT":
                            result["output_policy"] = policy
                        elif chain_name == "FORWARD":
                            result["forward_policy"] = policy
            else:
                result["error"] = proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the iptables default deny check.

        Returns:
            CheckResult with the outcome of the check
        """
        policy = self._get_iptables_policy()

        details = {
            "policy": policy,
        }

        # Check if iptables command failed
        if policy["error"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Failed to get iptables policy: {policy['error']}",
                remediation=(
                    "Ensure iptables is installed and accessible:\n"
                    "1. Install iptables: sudo dnf install iptables\n"
                    "2. Check permissions: sudo iptables -L"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        input_policy = policy.get("input_policy")
        output_policy = policy.get("output_policy")
        forward_policy = policy.get("forward_policy")

        # Check if policies are set to DROP
        input_ok = input_policy == "DROP"
        output_ok = output_policy == "DROP"
        forward_ok = forward_policy == "DROP"

        if input_ok and output_ok and forward_ok:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="iptables has default deny (DROP) policy for all chains",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not input_ok:
            issues.append(f"INPUT chain policy is {input_policy or 'not set'} (expected DROP)")
        if not output_ok:
            issues.append(f"OUTPUT chain policy is {output_policy or 'not set'} (expected DROP)")
        if not forward_ok:
            issues.append(f"FORWARD chain policy is {forward_policy or 'not set'} (expected DROP)")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"iptables default policy issues: {'; '.join(issues)}",
            remediation=(
                "Set default deny policy for iptables:\n"
                "1. Set default policies:\n"
                "   sudo iptables -P INPUT DROP\n"
                "   sudo iptables -P OUTPUT DROP\n"
                "   sudo iptables -P FORWARD DROP\n"
                "2. Add rules to allow necessary traffic before applying DROP policy:\n"
                "   sudo iptables -A INPUT -i lo -j ACCEPT\n"
                "   sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "   sudo iptables -A OUTPUT -o lo -j ACCEPT\n"
                "   sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "3. Save rules: sudo service iptables save\n"
                "   Or: sudo /usr/libexec/iptables/iptables.init save"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
