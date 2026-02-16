"""
CIS Audit Check: Network Services

Checks for suspicious or listening network services that may pose security risks.
"""

import os
import subprocess
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class NetworkServicesCheck(BaseCheck):
    """Check for suspicious or risky network services."""

    id = "network_services"
    name = "Network Services Audit"
    description = (
        "Identifies listening network services, especially those bound "
        "to all interfaces (0.0.0.0 or :::) and known risky services"
    )
    severity = Severity.HIGH
    requires_root = True

    # High-risk services that should be flagged
    HIGH_RISK_SERVICES = [
        "telnet", "telnetd",
        "ftp", "vsftpd", "proftpd", "pure-ftpd",
        "rsh", "rshd", "rlogin", "rlogind", "rexec", "rexecd",
        "tftp", "tftpd",
        "finger", "fingerd",
        "talk", "talkd", "ntalk",
        "uucp", "uucpd",
    ]

    # Medium-risk services that should be noted
    MEDIUM_RISK_SERVICES = [
        "ssh", "sshd",
        "vnc", "x11vnc", "tigervnc",
        "rdp", "xrdp",
        "nfs", "rpcbind", "mountd", "statd",
        "smb", "smbd", "nmbd", "samba",
    ]

    # Services that commonly listen on all interfaces (expected behavior)
    COMMON_ALL_INTERFACES = [
        "sshd", "httpd", "apache2", "nginx",
        "docker-proxy", "containerd",
    ]

    def _get_listening_services(self) -> dict:
        """Get list of listening network services using ss or netstat.

        Returns:
            Dictionary with listening services information
        """
        result = {
            "method": None,
            "services": [],
            "errors": [],
        }

        # Try ss command first (modern replacement for netstat)
        try:
            ss_result = subprocess.run(
                ["ss", "-tlnp", "-4"],  # TCP listening, numeric, processes, IPv4
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ss_result.returncode == 0:
                result["method"] = "ss"
                result["services"].extend(self._parse_ss_output(ss_result.stdout))

            # Also get IPv6
            ss6_result = subprocess.run(
                ["ss", "-tlnp", "-6"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ss6_result.returncode == 0:
                result["services"].extend(self._parse_ss_output(ss6_result.stdout, ipv6=True))

            # Get UDP as well
            ss_udp_result = subprocess.run(
                ["ss", "-ulnp", "-4"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ss_udp_result.returncode == 0:
                result["services"].extend(self._parse_ss_output(ss_udp_result.stdout, proto="udp"))

            return result

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["errors"].append(f"ss command failed: {str(e)}")

        # Fallback to netstat
        try:
            netstat_result = subprocess.run(
                ["netstat", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if netstat_result.returncode == 0:
                result["method"] = "netstat"
                result["services"].extend(self._parse_netstat_output(netstat_result.stdout))
                return result

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["errors"].append(f"netstat command failed: {str(e)}")

        return result

    def _parse_ss_output(self, output: str, ipv6: bool = False, proto: str = "tcp") -> list[dict]:
        """Parse ss command output.

        Args:
            output: Raw ss command output
            ipv6: Whether this is IPv6 output
            proto: Protocol (tcp or udp)

        Returns:
            List of service dictionaries
        """
        services = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("State"):
                continue

            # Parse ss output format:
            # LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
            # or
            # LISTEN 0 128 *:22 *:* users:(("sshd",pid=1234,fd=3))

            parts = line.split()
            if len(parts) < 5:
                continue

            state = parts[0]
            local_addr = parts[4] if len(parts) > 4 else ""

            # Extract port
            port_match = re.search(r':(\d+)$', local_addr)
            port = port_match.group(1) if port_match else "unknown"

            # Extract process info
            process_info = ""
            for part in parts:
                if "users:" in part or "pid=" in part:
                    process_info = part
                    break

            # Parse process name and PID
            process_name = "unknown"
            pid = None

            if process_info:
                # Extract from users:(("name",pid=1234,fd=3))
                name_match = re.search(r'\"([^\"]+)\"', process_info)
                if name_match:
                    process_name = name_match.group(1)

                pid_match = re.search(r'pid=(\d+)', process_info)
                if pid_match:
                    pid = pid_match.group(1)

            # Determine if listening on all interfaces
            listen_all = (
                local_addr.startswith("0.0.0.0:") or
                local_addr.startswith("[::]:") or
                local_addr.startswith("*:") or
                local_addr.startswith(":::")
            )

            services.append({
                "protocol": proto,
                "state": state,
                "local_address": local_addr,
                "port": port,
                "process_name": process_name,
                "pid": pid,
                "listen_all": listen_all,
                "ipv6": ipv6,
                "raw": line,
            })

        return services

    def _parse_netstat_output(self, output: str) -> list[dict]:
        """Parse netstat command output.

        Args:
            output: Raw netstat command output

        Returns:
            List of service dictionaries
        """
        services = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("Active") or line.startswith("Proto"):
                continue

            # Parse netstat output format:
            # tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
            parts = line.split()
            if len(parts) < 7:
                continue

            proto = parts[0]
            local_addr = parts[3]
            state = parts[5] if len(parts) > 5 else ""
            process_col = parts[6] if len(parts) > 6 else ""

            # Extract port
            port_match = re.search(r':(\d+)$', local_addr)
            port = port_match.group(1) if port_match else "unknown"

            # Parse process info (format: 1234/sshd or -)
            process_name = "unknown"
            pid = None

            if process_col and process_col != "-":
                pid_match = re.match(r'(\d+)/(.*)', process_col)
                if pid_match:
                    pid = pid_match.group(1)
                    process_name = pid_match.group(2)

            # Determine if listening on all interfaces
            listen_all = (
                local_addr.startswith("0.0.0.0:") or
                local_addr.startswith("[::]:") or
                local_addr.startswith(":::")
            )

            services.append({
                "protocol": proto,
                "state": state,
                "local_address": local_addr,
                "port": port,
                "process_name": process_name,
                "pid": pid,
                "listen_all": listen_all,
                "ipv6": "[::]" in local_addr or ":::" in local_addr,
                "raw": line,
            })

        return services

    def _analyze_services(self, services: list[dict]) -> dict:
        """Analyze services for risks.

        Args:
            services: List of service dictionaries

        Returns:
            Dictionary with analysis results
        """
        result = {
            "total_listening": len(services),
            "listening_on_all": [],
            "high_risk_found": [],
            "medium_risk_found": [],
            "by_port": {},
            "recommendations": [],
        }

        for svc in services:
            process_name = svc.get("process_name", "unknown").lower()
            port = svc.get("port", "unknown")

            # Track by port
            if port not in result["by_port"]:
                result["by_port"][port] = []
            result["by_port"][port].append(svc)

            # Check if listening on all interfaces
            if svc.get("listen_all", False):
                result["listening_on_all"].append(svc)

                # Check if this is unexpected
                if process_name not in [s.lower() for s in self.COMMON_ALL_INTERFACES]:
                    result["recommendations"].append(
                        f"{process_name} on port {port} is listening on all interfaces - "
                        f"consider binding to specific IPs if not required"
                    )

            # Check for high-risk services
            for risky in self.HIGH_RISK_SERVICES:
                if risky in process_name:
                    result["high_risk_found"].append({
                        "service": process_name,
                        "risk_type": "high",
                        "risk_reason": f"{process_name} is a known high-risk service",
                        "details": svc,
                    })
                    break

            # Check for medium-risk services
            for risky in self.MEDIUM_RISK_SERVICES:
                if risky in process_name:
                    result["medium_risk_found"].append({
                        "service": process_name,
                        "risk_type": "medium",
                        "risk_reason": f"{process_name} should be reviewed for necessity",
                        "details": svc,
                    })
                    break

        return result

    def _check_systemd_services(self) -> dict:
        """Check systemd for enabled network-related services.

        Returns:
            Dictionary with systemd service findings
        """
        result = {
            "checked": False,
            "enabled_services": [],
            "errors": [],
        }

        try:
            # Get list of enabled services
            svc_result = subprocess.run(
                ["systemctl", "list-unit-files", "--state=enabled", "--type=service", "--no-pager", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if svc_result.returncode == 0:
                result["checked"] = True

                for line in svc_result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split()
                    if parts:
                        service_name = parts[0].replace(".service", "")

                        # Check if it's a network service we're interested in
                        all_risky = self.HIGH_RISK_SERVICES + self.MEDIUM_RISK_SERVICES
                        for risky in all_risky:
                            if risky in service_name.lower():
                                result["enabled_services"].append({
                                    "service": service_name,
                                    "status": "enabled",
                                    "risk_indicator": risky,
                                })
                                break

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            result["errors"].append(str(e))

        return result

    def run(self) -> CheckResult:
        """Execute the network services check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "listening_services": {},
            "analysis": {},
            "systemd_services": {},
        }

        # Get listening services
        listening = self._get_listening_services()
        details["listening_services"] = listening

        if not listening["services"] and listening["errors"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not retrieve network service information: {'; '.join(listening['errors'])}",
                remediation=(
                    "Ensure network monitoring tools are available:\n"
                    "1. Install iproute package: sudo dnf install iproute\n"
                    "2. Or install net-tools: sudo dnf install net-tools\n"
                    "3. Verify with: ss -tlnp"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Analyze services
        analysis = self._analyze_services(listening["services"])
        details["analysis"] = analysis

        # Check systemd services
        systemd_info = self._check_systemd_services()
        details["systemd_services"] = systemd_info

        # Build result based on findings
        high_risk = analysis.get("high_risk_found", [])
        medium_risk = analysis.get("medium_risk_found", [])
        listening_all = analysis.get("listening_on_all", [])

        if high_risk:
            services_list = ", ".join([s["service"] for s in high_risk])
            ports_list = ", ".join(set([s["details"]["port"] for s in high_risk]))

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"High-risk network services detected: {services_list} on ports {ports_list}",
                remediation=(
                    "Remove or secure high-risk network services:\n"
                    "1. Identify services to remove:\n"
                    + "".join([f"   - {s['service']} on port {s['details']['port']}\n" for s in high_risk])
                    + "2. Stop and disable services:\n"
                    "   sudo systemctl stop <service>\n"
                    "   sudo systemctl disable <service>\n"
                    "3. Remove packages if not needed:\n"
                    "   sudo dnf remove <package>\n"
                    "4. Use secure alternatives:\n"
                    "   - Replace telnet with SSH\n"
                    "   - Replace FTP with SFTP/SCP\n"
                    "   - Replace rsh/rlogin with SSH"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build informational message
        total_svc = analysis.get("total_listening", 0)
        all_ifaces_count = len(listening_all)

        message_parts = [f"Found {total_svc} listening network services"]

        if all_ifaces_count > 0:
            message_parts.append(f"{all_ifaces_count} listening on all interfaces")

        if medium_risk:
            svc_names = ", ".join(set([s["service"] for s in medium_risk]))
            message_parts.append(f"review recommended for: {svc_names}")

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="; ".join(message_parts),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
