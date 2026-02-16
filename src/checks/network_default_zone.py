"""
CIS Audit Check: FirewallD Default Zone

Checks if firewalld default zone is configured with reasonable restrictions.
"""

import os
import subprocess
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class FirewalldDefaultZoneCheck(BaseCheck):
    """Check for firewalld default zone configuration."""

    id = "network_default_zone"
    name = "FirewallD Default Zone Configuration"
    description = (
        "Verifies that firewalld has a default zone configured "
        "with reasonable security restrictions"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Risky services that should not be open by default
    RISKY_SERVICES = [
        "telnet", "ftp", "ssh", "http", "https",
        "mysql", "postgresql", "mongodb", "redis",
        "vnc", "rdp", "smb", "nfs",
    ]

    def _get_default_zone(self) -> tuple[str | None, str]:
        """Get the current default zone.

        Returns:
            Tuple of (zone_name, raw_output)
        """
        try:
            result = subprocess.run(
                ["firewall-cmd", "--get-default-zone"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                zone = result.stdout.strip()
                return zone if zone else None, result.stdout.strip()
            return None, result.stderr.strip() or result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return None, str(e)

    def _get_active_zones(self) -> tuple[list[str], str]:
        """Get list of active zones.

        Returns:
            Tuple of (zones_list, raw_output)
        """
        try:
            result = subprocess.run(
                ["firewall-cmd", "--get-active-zones"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse zone names from output (zone names are not indented)
                zones = []
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("interfaces:") and not line.startswith("sources:"):
                        zones.append(line)
                return zones, result.stdout.strip()
            return [], result.stderr.strip() or result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return [], str(e)

    def _get_zone_services(self, zone: str) -> tuple[list[str], str]:
        """Get services configured for a zone.

        Args:
            zone: Zone name to query

        Returns:
            Tuple of (services_list, raw_output)
        """
        try:
            result = subprocess.run(
                ["firewall-cmd", "--zone", zone, "--list-services"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                services = [s.strip() for s in result.stdout.strip().split() if s.strip()]
                return services, result.stdout.strip()
            return [], result.stderr.strip() or result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return [], str(e)

    def _get_zone_target(self, zone: str) -> tuple[str | None, str]:
        """Get target policy for a zone.

        Args:
            zone: Zone name to query

        Returns:
            Tuple of (target, raw_output)
        """
        try:
            result = subprocess.run(
                ["firewall-cmd", "--zone", zone, "--get-target"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                target = result.stdout.strip()
                return target if target else None, result.stdout.strip()
            return None, result.stderr.strip() or result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return None, str(e)

    def _check_zone_file(self, zone: str) -> dict:
        """Check zone configuration file for additional details.

        Args:
            zone: Zone name to check

        Returns:
            Dictionary with file configuration details
        """
        details = {
            "file_exists": False,
            "file_path": None,
            "short_description": None,
            "target": None,
        }

        # Check both system and custom zone files
        paths = [
            f"/etc/firewalld/zones/{zone}.xml",
            f"/usr/lib/firewalld/zones/{zone}.xml",
        ]

        for path in paths:
            if os.path.exists(path):
                details["file_exists"] = True
                details["file_path"] = path
                try:
                    with open(path, "r") as f:
                        content = f.read()

                    # Extract short description
                    desc_match = re.search(r'<short>([^<]+)</short>', content)
                    if desc_match:
                        details["short_description"] = desc_match.group(1)

                    # Extract target
                    target_match = re.search(r'target="([^"]+)"', content)
                    if target_match:
                        details["target"] = target_match.group(1)

                except (IOError, OSError):
                    pass
                break

        return details

    def run(self) -> CheckResult:
        """Execute the default zone check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "firewalld_available": True,
            "default_zone": None,
            "active_zones": [],
            "zone_services": [],
            "zone_target": None,
            "file_config": {},
            "risky_services_found": [],
        }

        # Check if firewall-cmd is available
        try:
            result = subprocess.run(
                ["firewall-cmd", "--state"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                details["firewalld_available"] = False
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="firewalld is not running - cannot check default zone configuration",
                    remediation=(
                        "Start firewalld to check zone configuration:\n"
                        "1. sudo systemctl start firewalld\n"
                        "2. Re-run this check"
                    ),
                    severity=self.severity,
                    requires_root=self.requires_root,
                    details=details,
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            details["firewalld_available"] = False
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="firewall-cmd command not available",
                remediation="Install and start firewalld to perform this check",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Get default zone
        default_zone, zone_output = self._get_default_zone()
        details["default_zone"] = default_zone
        details["default_zone_raw_output"] = zone_output

        if not default_zone:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="No default zone is configured in firewalld",
                remediation=(
                    "Set a default zone in firewalld:\n"
                    "1. List available zones: sudo firewall-cmd --get-zones\n"
                    "2. Set default zone: sudo firewall-cmd --set-default-zone=public\n"
                    "3. Make permanent: sudo firewall-cmd --runtime-to-permanent\n\n"
                    "Recommended zones:\n"
                    "- 'public': For use in public areas (most restrictive)\n"
                    "- 'home': For home networks\n"
                    "- 'internal': For internal networks"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Get active zones
        active_zones, active_output = self._get_active_zones()
        details["active_zones"] = active_zones
        details["active_zones_raw_output"] = active_output

        # Get services for default zone
        services, services_output = self._get_zone_services(default_zone)
        details["zone_services"] = services
        details["zone_services_raw_output"] = services_output

        # Get target for default zone
        target, target_output = self._get_zone_target(default_zone)
        details["zone_target"] = target
        details["zone_target_raw_output"] = target_output

        # Check zone configuration file
        details["file_config"] = self._check_zone_file(default_zone)

        # Check for risky services
        risky_found = []
        for service in services:
            service_lower = service.lower()
            for risky in self.RISKY_SERVICES:
                if risky in service_lower:
                    risky_found.append(service)
                    break
        details["risky_services_found"] = risky_found

        # Determine if configuration is reasonable
        issues = []

        # Check if default zone is overly permissive
        if default_zone == "trusted":
            issues.append("Default zone 'trusted' allows all traffic - not recommended")

        # Check target policy
        if target == "ACCEPT":
            issues.append(f"Zone target is ACCEPT (allows all traffic not explicitly rejected)")

        # Check for risky services
        if risky_found:
            issues.append(f"Potentially risky services are open: {', '.join(risky_found)}")

        # Check if SSH is open on default zone (common but should be noted)
        if "ssh" in services:
            details["ssh_open"] = True
        else:
            details["ssh_open"] = False

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Default zone '{default_zone}' has configuration issues: {'; '.join(issues)}",
                remediation=(
                    f"Review and tighten default zone '{default_zone}' configuration:\n"
                    f"1. View current config: sudo firewall-cmd --zone={default_zone} --list-all\n"
                    f"2. Remove risky services:\n"
                    + "".join([f"   sudo firewall-cmd --zone={default_zone} --remove-service={s}\n" for s in risky_found])
                    + f"3. Change to more restrictive zone if needed:\n"
                    f"   sudo firewall-cmd --set-default-zone=public\n"
                    f"4. Make changes permanent:\n"
                    f"   sudo firewall-cmd --runtime-to-permanent"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Default zone '{default_zone}' is properly configured with {len(services)} services",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
