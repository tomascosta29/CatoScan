"""
CIS Audit Check: GDM Login Banner Configured (1.7.2)

Ensures that GDM (GNOME Display Manager) login banner is configured
with a proper warning message.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class GDMBannerCheck(BaseCheck):
    """Check GDM login banner configuration."""

    id = "gdm_banner"
    name = "GDM Login Banner Configured"
    description = (
        "Verifies that GDM login banner is configured with a proper warning message"
    )
    severity = Severity.MEDIUM
    requires_root = True

    GDM_CONF_PATH = "/etc/gdm/custom.conf"
    GDM_PROFILE_PATH = "/etc/dconf/profile/gdm"
    GREETER_DCONF_DIR = "/etc/dconf/db/gdm.d"
    GREETER_DCONF_PATH = "/etc/dconf/db/gdm.d/01-banner-message"

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
            # If we can't check, assume it might be installed
            return True

    def _check_custom_conf(self) -> dict:
        """Check /etc/gdm/custom.conf for banner settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "file_exists": False,
            "banner_text_enabled": False,
            "banner_text": None,
        }

        path = Path(self.GDM_CONF_PATH)
        if not path.exists():
            return result

        result["file_exists"] = True

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result["content"] = content

            # Look for banner-message-enable and banner-message-text in greeter section
            in_greeter = False
            for line in content.split("\n"):
                line = line.strip()

                if line.startswith("[greeter]"):
                    in_greeter = True
                    continue
                elif line.startswith("[") and line.endswith("]"):
                    in_greeter = False
                    continue

                if in_greeter:
                    if "banner-message-enable" in line:
                        if "true" in line.lower():
                            result["banner_text_enabled"] = True
                    elif "banner-message-text" in line:
                        match = re.search(r'banner-message-text\s*=\s*"?([^"\n]+)"?', line)
                        if match:
                            result["banner_text"] = match.group(1)

        except (IOError, OSError):
            pass

        return result

    def _check_dconf_settings(self) -> dict:
        """Check dconf settings for GDM banner.

        Returns:
            Dictionary with dconf configuration
        """
        result = {
            "profile_exists": False,
            "db_dir_exists": False,
            "banner_config_exists": False,
            "banner_enabled": False,
            "banner_text": None,
        }

        # Check profile
        profile_path = Path(self.GDM_PROFILE_PATH)
        if profile_path.exists():
            result["profile_exists"] = True

        # Check dconf db directory
        db_dir = Path(self.GREETER_DCONF_DIR)
        if db_dir.exists() and db_dir.is_dir():
            result["db_dir_exists"] = True

        # Check banner config file
        banner_path = Path(self.GREETER_DCONF_PATH)
        if banner_path.exists():
            result["banner_config_exists"] = True
            try:
                content = banner_path.read_text(encoding="utf-8", errors="ignore")
                result["content"] = content

                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("#"):
                        continue

                    if "banner-message-enable" in line:
                        if "true" in line.lower():
                            result["banner_enabled"] = True
                    elif "banner-message-text" in line:
                        match = re.search(r'banner-message-text\s*=\s*["\']([^"\']+)["\']', line)
                        if match:
                            result["banner_text"] = match.group(1)

            except (IOError, OSError):
                pass

        return result

    def run(self) -> CheckResult:
        """Execute the GDM banner check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if GDM is installed
        if not self._check_gdm_installed():
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="GDM is not installed - banner check not applicable",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"gdm_installed": False},
            )

        custom_conf = self._check_custom_conf()
        dconf_settings = self._check_dconf_settings()

        details = {
            "gdm_installed": True,
            "custom_conf": custom_conf,
            "dconf_settings": dconf_settings,
        }

        # Check if banner is configured via either method
        banner_enabled = (
            custom_conf.get("banner_text_enabled") or
            dconf_settings.get("banner_enabled")
        )
        banner_text = (
            custom_conf.get("banner_text") or
            dconf_settings.get("banner_text")
        )

        if banner_enabled and banner_text:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"GDM login banner is configured: '{banner_text[:50]}...' " if len(banner_text) > 50 else f"GDM login banner is configured: '{banner_text}'",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if banner_enabled and not banner_text:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="GDM banner is enabled but no banner text is configured",
                remediation=(
                    "Configure GDM banner text:\n\n"
                    "Method 1 - Using /etc/gdm/custom.conf:\n"
                    "  [greeter]\n"
                    "  banner-message-enable=true\n"
                    '  banner-message-text="Authorized uses only. All activity may be monitored and reported."\n\n'
                    "Method 2 - Using dconf:\n"
                    f"  Create {self.GREETER_DCONF_PATH} with:\n"
                    "  [org/gnome/login-screen]\n"
                    "  banner-message-enable=true\n"
                    '  banner-message-text="Authorized uses only. All activity may be monitored and reported."\n\n'
                    "Then run: sudo dconf update"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="GDM login banner is not configured",
            remediation=(
                "Enable and configure GDM login banner:\n\n"
                "Method 1 - Using /etc/gdm/custom.conf:\n"
                "  sudo nano /etc/gdm/custom.conf\n\n"
                "Add under [greeter] section:\n"
                "  banner-message-enable=true\n"
                '  banner-message-text="Authorized uses only. All activity may be monitored and reported."\n\n'
                "Method 2 - Using dconf:\n"
                f"  sudo mkdir -p {self.GREETER_DCONF_DIR}\n"
                f"  sudo nano {self.GREETER_DCONF_PATH}\n\n"
                "Add:\n"
                "  [org/gnome/login-screen]\n"
                "  banner-message-enable=true\n"
                '  banner-message-text="Authorized uses only. All activity may be monitored and reported."\n\n'
                "Then run: sudo dconf update"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
