"""
CIS Audit Check: GDM Disable User List (1.7.3)

Ensures that GDM (GNOME Display Manager) does not display the user list
on the login screen for security.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class GDMDisableUserListCheck(BaseCheck):
    """Check GDM disable-user-list configuration."""

    id = "gdm_disable_user_list"
    name = "GDM Disable User List"
    description = (
        "Verifies that GDM is configured to disable the user list on the login screen"
    )
    severity = Severity.MEDIUM
    requires_root = True

    GDM_CONF_PATH = "/etc/gdm/custom.conf"
    GREETER_DCONF_DIR = "/etc/dconf/db/gdm.d"
    GREETER_DCONF_PATH = "/etc/dconf/db/gdm.d/00-login-screen"

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

    def _check_custom_conf(self) -> dict:
        """Check /etc/gdm/custom.conf for disable-user-list settings.

        Returns:
            Dictionary with configuration findings
        """
        result = {
            "file_exists": False,
            "disable_user_list": False,
        }

        path = Path(self.GDM_CONF_PATH)
        if not path.exists():
            return result

        result["file_exists"] = True

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result["content"] = content

            # Look for disable-user-list in greeter section
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
                    if "disable-user-list" in line.lower():
                        if "true" in line.lower():
                            result["disable_user_list"] = True

        except (IOError, OSError):
            pass

        return result

    def _check_dconf_settings(self) -> dict:
        """Check dconf settings for GDM user list.

        Returns:
            Dictionary with dconf configuration
        """
        result = {
            "db_dir_exists": False,
            "config_exists": False,
            "disable_user_list": False,
        }

        # Check dconf db directory
        db_dir = Path(self.GREETER_DCONF_DIR)
        if db_dir.exists() and db_dir.is_dir():
            result["db_dir_exists"] = True

            # Check all files in the directory
            for conf_file in db_dir.glob("*.conf"):
                result["config_exists"] = True
                try:
                    content = conf_file.read_text(encoding="utf-8", errors="ignore")

                    for line in content.split("\n"):
                        line = line.strip()
                        if line.startswith("#"):
                            continue

                        if "disable-user-list" in line.lower():
                            if "true" in line.lower():
                                result["disable_user_list"] = True
                                result["config_file"] = str(conf_file)

                except (IOError, OSError):
                    pass

        return result

    def run(self) -> CheckResult:
        """Execute the GDM disable user list check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if GDM is installed
        if not self._check_gdm_installed():
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="GDM is not installed - check not applicable",
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

        # Check if disable-user-list is enabled via either method
        user_list_disabled = (
            custom_conf.get("disable_user_list") or
            dconf_settings.get("disable_user_list")
        )

        if user_list_disabled:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="GDM user list is disabled on login screen",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="GDM user list is not disabled on login screen",
            remediation=(
                "Disable GDM user list:\n\n"
                "Method 1 - Using /etc/gdm/custom.conf:\n"
                "  sudo nano /etc/gdm/custom.conf\n\n"
                "Add under [greeter] section:\n"
                "  disable-user-list=true\n\n"
                "Method 2 - Using dconf:\n"
                f"  sudo mkdir -p {self.GREETER_DCONF_DIR}\n"
                f"  sudo nano {self.GREETER_DCONF_PATH}\n\n"
                "Add:\n"
                "  [org/gnome/login-screen]\n"
                "  disable-user-list=true\n\n"
                "Then run: sudo dconf update\n\n"
                "CIS Benchmark: 1.7.3 - Ensure disable-user-list is enabled"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
