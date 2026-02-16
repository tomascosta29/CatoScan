"""
CIS Audit Check: IPv6 Configuration

Checks if IPv6 is disabled (if required by policy).
Note: IPv6 may be intentionally enabled - this is informational.
"""

import glob
import os
import re
import subprocess
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class IPv6Check(BaseCheck):
    """Check for IPv6 configuration status."""

    id = "network_ipv6"
    name = "IPv6 Configuration"
    description = (
        "Checks if IPv6 is disabled via kernel parameters or sysctl. "
        "Note: IPv6 may be intentionally enabled per organizational policy."
    )
    severity = Severity.LOW
    requires_root = True

    # Kernel parameter files to check
    KERNEL_CMDLINE_PATHS = [
        "/proc/cmdline",
    ]

    # Sysctl configuration files
    SYSCTL_PATHS = [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/*.conf",
        "/usr/lib/sysctl.d/*.conf",
        "/run/sysctl.d/*.conf",
    ]

    # Network configuration files
    DEFAULT_NETWORK_CONFIG_PATHS = [
        "/etc/sysconfig/network",
        "/etc/sysconfig/network-scripts/ifcfg-*",
        "/etc/NetworkManager/system-connections/*",
    ]

    def _get_network_config_paths(self) -> list[str]:
        """Get platform-aware network config path patterns.

        Returns:
            Ordered list of path patterns for network config files
        """
        paths = self.platform_context.get_paths("network_config_paths")
        if paths:
            return paths
        return self.DEFAULT_NETWORK_CONFIG_PATHS

    def _check_kernel_params(self) -> dict:
        """Check kernel command line for IPv6 disable flags.

        Returns:
            Dictionary with kernel parameter findings
        """
        result = {
            "checked": False,
            "ipv6_disabled": False,
            "method": None,
            "details": [],
        }

        for path in self.KERNEL_CMDLINE_PATHS:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        content = f.read()
                    result["checked"] = True

                    # Check for various IPv6 disable methods
                    if "ipv6.disable=1" in content:
                        result["ipv6_disabled"] = True
                        result["method"] = "kernel_cmdline"
                        result["details"].append(f"Found 'ipv6.disable=1' in {path}")

                    if "ipv6.disable_ipv6=1" in content:
                        result["ipv6_disabled"] = True
                        result["method"] = "kernel_cmdline"
                        result["details"].append(f"Found 'ipv6.disable_ipv6=1' in {path}")

                except (IOError, OSError) as e:
                    result["details"].append(f"Error reading {path}: {str(e)}")

        return result

    def _check_sysctl_config(self) -> dict:
        """Check sysctl configuration for IPv6 settings.

        Returns:
            Dictionary with sysctl findings
        """
        result = {
            "checked": False,
            "ipv6_disabled": False,
            "all_disabled": False,
            "per_interface": {},
            "config_files": [],
            "details": [],
        }

        # Check using sysctl command first
        try:
            sysctl_result = subprocess.run(
                ["sysctl", "-a"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if sysctl_result.returncode == 0:
                result["checked"] = True

                # Check net.ipv6.conf.all.disable_ipv6
                for line in sysctl_result.stdout.split("\n"):
                    if "net.ipv6.conf.all.disable_ipv6" in line:
                        match = re.search(r'=\s*(\d+)', line)
                        if match and match.group(1) == "1":
                            result["all_disabled"] = True
                            result["details"].append("net.ipv6.conf.all.disable_ipv6 = 1")

                    # Check per-interface settings
                    iface_match = re.search(r'net\.ipv6\.conf\.(\w+)\.disable_ipv6\s*=\s*(\d+)', line)
                    if iface_match:
                        iface, value = iface_match.groups()
                        result["per_interface"][iface] = value == "1"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Check configuration files
        for pattern in self.SYSCTL_PATHS:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    try:
                        with open(path, "r") as f:
                            content = f.read()

                        if "disable_ipv6" in content or "ipv6" in content.lower():
                            result["config_files"].append(path)

                            # Check for disable settings
                            for line in content.split("\n"):
                                line = line.strip()
                                if line.startswith("#"):
                                    continue

                                if "net.ipv6.conf.all.disable_ipv6" in line:
                                    match = re.search(r'=\s*(\d+)', line)
                                    if match and match.group(1) == "1":
                                        result["all_disabled"] = True
                                        result["details"].append(f"{path}: {line}")

                    except (IOError, OSError):
                        pass

        # Overall IPv6 is considered disabled if all interfaces are disabled
        result["ipv6_disabled"] = result["all_disabled"]

        return result

    def _check_network_config(self) -> dict:
        """Check network configuration files for IPv6 settings.

        Returns:
            Dictionary with network config findings
        """
        result = {
            "checked": False,
            "ipv6_disabled": False,
            "config_files": [],
            "details": [],
        }

        disable_markers = [
            "NETWORKING_IPV6=no",
            "IPV6INIT=no",
            "ipv6.method=disabled",
        ]

        seen_files: set[str] = set()

        for pattern in self._get_network_config_paths():
            candidate_paths: list[str]
            if any(char in pattern for char in "*?[]"):
                candidate_paths = glob.glob(pattern)
            else:
                candidate_paths = [pattern]

            for path in sorted(candidate_paths):
                if path in seen_files or not os.path.isfile(path):
                    continue

                seen_files.add(path)

                try:
                    with open(path, "r") as f:
                        content = f.read()
                except (IOError, OSError):
                    continue

                result["checked"] = True
                result["config_files"].append(path)

                for line in content.split("\n"):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                        continue

                    normalized = stripped.replace(" ", "")
                    if any(marker in normalized for marker in disable_markers):
                        result["ipv6_disabled"] = True
                        result["details"].append(f"{path}: {stripped}")

        return result

    def _check_ipv6_interfaces(self) -> dict:
        """Check if any interfaces have IPv6 addresses assigned.

        Returns:
            Dictionary with interface findings
        """
        result = {
            "checked": False,
            "ipv6_active": False,
            "interfaces": {},
        }

        try:
            # Check using ip command
            ip_result = subprocess.run(
                ["ip", "-6", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if ip_result.returncode == 0:
                result["checked"] = True

                # Parse output for interfaces with IPv6 addresses
                current_iface = None
                for line in ip_result.stdout.split("\n"):
                    # Interface line
                    iface_match = re.match(r'^\d+:\s+(\w+):', line)
                    if iface_match:
                        current_iface = iface_match.group(1)
                        result["interfaces"][current_iface] = {
                            "has_global": False,
                            "has_link_local": False,
                            "addresses": [],
                        }

                    # IPv6 address line
                    if "inet6" in line and current_iface:
                        addr_match = re.search(r'inet6\s+([\da-fA-F:]+)', line)
                        if addr_match:
                            addr = addr_match.group(1)
                            result["interfaces"][current_iface]["addresses"].append(addr)

                            # Check for link-local vs global
                            if addr.startswith("fe80:"):
                                result["interfaces"][current_iface]["has_link_local"] = True
                            elif not addr.startswith("::1"):
                                result["interfaces"][current_iface]["has_global"] = True
                                result["ipv6_active"] = True

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the IPv6 configuration check.

        Returns:
            CheckResult with the outcome of the check
        """
        details = {
            "kernel_params": {},
            "sysctl_config": {},
            "network_config": {},
            "interface_status": {},
            "ipv6_disabled": False,
            "disable_method": None,
        }

        # Check kernel parameters
        kernel_result = self._check_kernel_params()
        details["kernel_params"] = kernel_result

        # Check sysctl configuration
        sysctl_result = self._check_sysctl_config()
        details["sysctl_config"] = sysctl_result

        # Check network configuration files
        network_result = self._check_network_config()
        details["network_config"] = network_result

        # Check interface status
        interface_result = self._check_ipv6_interfaces()
        details["interface_status"] = interface_result

        # Determine overall IPv6 status
        ipv6_disabled = (
            kernel_result.get("ipv6_disabled", False) or
            sysctl_result.get("ipv6_disabled", False) or
            network_result.get("ipv6_disabled", False)
        )

        details["ipv6_disabled"] = ipv6_disabled

        # Determine disable method
        if kernel_result.get("ipv6_disabled"):
            details["disable_method"] = "kernel_parameter"
        elif sysctl_result.get("ipv6_disabled"):
            details["disable_method"] = "sysctl"
        elif network_result.get("ipv6_disabled"):
            details["disable_method"] = "network_config"

        # Build message based on findings
        if ipv6_disabled:
            method_str = details["disable_method"] or "unknown method"
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"IPv6 is disabled via {method_str}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # IPv6 is enabled - this is informational, not a failure
        if interface_result.get("ipv6_active", False):
            active_ifaces = [
                iface for iface, data in interface_result.get("interfaces", {}).items()
                if data.get("has_global", False)
            ]
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"IPv6 is enabled and active on interfaces: {', '.join(active_ifaces)}. This is informational - review if IPv6 should be disabled per organizational policy.",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # IPv6 might be enabled but not actively used
        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="IPv6 appears to be enabled in configuration but no active global addresses found. Review if IPv6 should be explicitly disabled per organizational policy.",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
