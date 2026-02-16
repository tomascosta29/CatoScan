"""
CIS Audit Check: iptables Firewall Rules for Open Ports (3.6.5)

Ensures iptables has firewall rules configured for all open ports.
"""

import subprocess
import re

from src.core.check import BaseCheck, CheckResult, Severity


class IPTablesOpenPortsCheck(BaseCheck):
    """Check if iptables has rules for open ports."""

    id = "iptables_open_ports"
    name = "iptables Rules for Open Ports"
    description = (
        "Verifies that iptables has explicit firewall rules for all open ports "
        "on the system"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _get_listening_ports(self) -> dict:
        """Get list of listening ports from system.

        Returns:
            Dictionary with listening ports
        """
        result = {
            "tcp_ports": [],
            "udp_ports": [],
            "error": None,
        }

        # Get listening TCP ports
        try:
            proc = subprocess.run(
                ["ss", "-tln"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                for line in proc.stdout.split("\n")[1:]:  # Skip header
                    if line.strip():
                        # Parse: State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
                        parts = line.split()
                        if len(parts) >= 5:
                            local_addr = parts[4]
                            if ":" in local_addr:
                                port = local_addr.split(":")[-1]
                                if port.isdigit():
                                    result["tcp_ports"].append(int(port))
            else:
                result["error"] = proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            # Fallback to netstat if ss is not available
            try:
                proc = subprocess.run(
                    ["netstat", "-tln"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0:
                    for line in proc.stdout.split("\n")[2:]:  # Skip headers
                        if line.strip() and not line.startswith("Proto"):
                            parts = line.split()
                            if len(parts) >= 4:
                                local_addr = parts[3]
                                if ":" in local_addr:
                                    port = local_addr.split(":")[-1]
                                    if port.isdigit():
                                        result["tcp_ports"].append(int(port))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                result["error"] = str(e)

        # Get listening UDP ports
        try:
            proc = subprocess.run(
                ["ss", "-uln"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                for line in proc.stdout.split("\n")[1:]:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            local_addr = parts[4]
                            if ":" in local_addr:
                                port = local_addr.split(":")[-1]
                                if port.isdigit():
                                    result["udp_ports"].append(int(port))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Remove duplicates and sort
        result["tcp_ports"] = sorted(set(result["tcp_ports"]))
        result["udp_ports"] = sorted(set(result["udp_ports"]))

        return result

    def _get_iptables_rules(self) -> dict:
        """Get iptables rules.

        Returns:
            Dictionary with rules
        """
        result = {
            "input_rules": [],
            "iptables_output": None,
            "error": None,
        }

        try:
            proc = subprocess.run(
                ["iptables", "-L", "INPUT", "-v", "-n"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                result["iptables_output"] = proc.stdout
                
                for line in proc.stdout.split("\n"):
                    # Parse rules (lines starting with a number)
                    if re.match(r'^\s*\d+', line):
                        result["input_rules"].append(line.strip())
            else:
                result["error"] = proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["error"] = str(e)

        return result

    def _check_port_rules(self, ports: dict, rules: list) -> dict:
        """Check if ports have corresponding iptables rules.

        Args:
            ports: Dictionary with tcp_ports and udp_ports
            rules: List of iptables rules

        Returns:
            Dictionary with check results
        """
        result = {
            "tcp_covered": [],
            "tcp_uncovered": [],
            "udp_covered": [],
            "udp_uncovered": [],
            "rules_found": [],
        }

        # Common ports that should be explicitly allowed
        common_tcp_ports = {22, 80, 443}  # SSH, HTTP, HTTPS
        
        # Check TCP ports
        for port in ports.get("tcp_ports", []):
            port_covered = False
            for rule in rules:
                # Check for dpt:PORT or --dport PORT
                if f"dpt:{port}" in rule or f"--dport {port}" in rule:
                    if "ACCEPT" in rule:
                        port_covered = True
                        result["rules_found"].append(f"TCP port {port}: {rule}")
                        break
            
            if port_covered:
                result["tcp_covered"].append(port)
            elif port in common_tcp_ports:
                # Only flag common ports as uncovered
                result["tcp_uncovered"].append(port)

        # Check UDP ports
        for port in ports.get("udp_ports", []):
            port_covered = False
            for rule in rules:
                if f"dpt:{port}" in rule or f"--dport {port}" in rule:
                    if "ACCEPT" in rule:
                        port_covered = True
                        result["rules_found"].append(f"UDP port {port}: {rule}")
                        break
            
            if port_covered:
                result["udp_covered"].append(port)
            # Only check common UDP ports (DNS, NTP)
            elif port in [53, 123]:
                result["udp_uncovered"].append(port)

        return result

    def run(self) -> CheckResult:
        """Execute the iptables open ports check.

        Returns:
            CheckResult with the outcome of the check
        """
        ports = self._get_listening_ports()
        rules = self._get_iptables_rules()

        # Check if commands failed
        if ports["error"] and not ports["tcp_ports"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Failed to get listening ports: {ports['error']}",
                remediation=(
                    "Ensure network tools are installed:\n"
                    "1. Install iproute/ss: sudo dnf install iproute\n"
                    "2. Or install net-tools: sudo dnf install net-tools"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"ports": ports, "rules": rules},
            )

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
                details={"ports": ports, "rules": rules},
            )

        port_check = self._check_port_rules(ports, rules.get("input_rules", []))

        details = {
            "ports": ports,
            "rules": rules,
            "port_check": port_check,
        }

        # Check if there are uncovered common ports
        uncovered_tcp = port_check["tcp_uncovered"]
        uncovered_udp = port_check["udp_uncovered"]

        if not uncovered_tcp and not uncovered_udp:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="iptables has firewall rules for open ports",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if uncovered_tcp:
            issues.append(f"TCP ports without explicit rules: {uncovered_tcp}")
        if uncovered_udp:
            issues.append(f"UDP ports without explicit rules: {uncovered_udp}")

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"iptables port rule issues: {'; '.join(issues)}",
            remediation=(
                "Configure iptables rules for open ports:\n"
                "1. Add rules for each open port (example for SSH port 22):\n"
                "   sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT\n"
                "2. Add rules for other services (HTTP/HTTPS):\n"
                "   sudo iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT\n"
                "   sudo iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT\n"
                "3. View open ports: sudo ss -tln\n"
                "4. Save rules: sudo service iptables save\n"
                "   Or: sudo /usr/libexec/iptables/iptables.init save"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
