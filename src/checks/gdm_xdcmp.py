"""
CIS Audit Check: GDM XDCMP Not Enabled (1.7.4)

Ensures that X Display Manager Control Protocol (XDCMP) is not enabled
in GDM configuration, as it allows remote users to connect to the display
manager over the network.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class GDMXDCMPCheck(BaseCheck):
    """Check GDM XDCMP configuration."""

    id = "gdm_xdcmp"
    name = "GDM XDCMP Not Enabled"
    description = (
        "Verifies that X Display Manager Control Protocol (XDCMP) is not enabled "
        "in GDM configuration"
    )
    severity = Severity.MEDIUM
    requires_root = True

    GDM_CONF_PATH = "/etc/gdm/custom.conf"

    def _check_gdm_installed(self) -> bool:
        """Check if GDM is installed.

        Returns:
            True if GDM is installed
        """
        try:
            import subprocess
            result = subprocess.run(
                ["rpm", "-q", "gdm"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return True

    def _check_xdcmp_settings(self) -> dict:
        """Check /etc/gdm/custom.conf for XDCMP settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "file_exists": False,
            "xdcmp_enabled": False,
            "enable_xdmcp": False,
            "max_sessions": None,
            "port": None,
            "settings_found": [],
        }

        path = Path(self.GDM_CONF_PATH)
        if not path.exists():
            return result

        result["file_exists"] = True

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result["content"] = content

            # Look for xdmcp section
            in_xdmcp = False
            for line_num, line in enumerate(content.split("\n"), 1):
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if line.startswith("[xdmcp]"):
                    in_xdmcp = True
                    continue
                elif line.startswith("[") and line.endswith("]"):
                    in_xdmcp = False
                    continue

                if in_xdmcp:
                    # Check for Enable setting
                    if re.search(r'^Enable\s*=\s*true', line, re.IGNORECASE):
                        result["xdcmp_enabled"] = True
                        result["enable_xdmcp"] = True
                        result["settings_found"].append(f"Enable=true at line {line_num}")

                    # Check for MaxSessions (indicates XDCMP is being configured)
                    match = re.search(r'^MaxSessions\s*=\s*(\d+)', line, re.IGNORECASE)
                    if match:
                        result["max_sessions"] = int(match.group(1))
                        result["settings_found"].append(f"MaxSessions={match.group(1)} at line {line_num}")

                    # Check for Port setting
                    match = re.search(r'^Port\s*=\s*(\d+)', line, re.IGNORECASE)
                    if match:
                        result["port"] = int(match.group(1))
                        result["settings_found"].append(f"Port={match.group(1)} at line {line_num}")

        except (IOError, OSError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the GDM XDCMP check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if GDM is installed
        if not self._check_gdm_installed():
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="GDM is not installed - XDCMP check not applicable",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"gdm_installed": False},
            )

        xdcmp_config = self._check_xdcmp_settings()

        details = {
            "gdm_installed": True,
            "xdcmp_config": xdcmp_config,
        }

        # Check if XDCMP is enabled
        if xdcmp_config.get("xdcmp_enabled") or xdcmp_config.get("enable_xdmcp"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="XDCMP is enabled in GDM configuration",
                remediation=(
                    "Disable XDCMP in GDM:\n\n"
                    "1. Edit /etc/gdm/custom.conf:\n"
                    "   sudo nano /etc/gdm/custom.conf\n\n"
                    "2. Find the [xdmcp] section and ensure it is either:\n"
                    "   - Not present, OR\n"
                    "   - Has Enable=false, OR\n"
                    "   - Is commented out\n\n"
                    "Example secure configuration:\n"
                    "   [xdmcp]\n"
                    "   Enable=false\n\n"
                    "3. Restart GDM:\n"
                    "   sudo systemctl restart gdm\n\n"
                    "CIS Benchmark: 1.7.4 - Ensure XDCMP is not enabled\n\n"
                    "Note: XDCMP allows remote users to connect to the display manager "
                    "over the network and should be disabled unless specifically required."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if xdmcp section exists with any settings (potential misconfiguration)
        if xdcmp_config.get("settings_found"):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"XDCMP section exists with settings: {', '.join(xdcmp_config['settings_found'])}",
                remediation=(
                    "Remove or disable XDCMP configuration:\n\n"
                    "1. Edit /etc/gdm/custom.conf:\n"
                    "   sudo nano /etc/gdm/custom.conf\n\n"
                    "2. Remove or comment out the entire [xdmcp] section\n\n"
                    "3. Restart GDM:\n"
                    "   sudo systemctl restart gdm"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="XDCMP is not enabled in GDM configuration",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
