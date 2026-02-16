"""
CIS Audit Check: Single User Mode Authentication (CIS 1.3.3)

Checks if authentication is required for single-user (rescue) mode
to prevent unauthorized access during system recovery.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class SingleUserAuthCheck(BaseCheck):
    """Check if authentication is required for single-user mode."""

    id = "boot_single_user_auth"
    name = "Single User Mode Authentication"
    description = (
        "Verifies that authentication is required when booting into "
        "single-user (rescue) mode to prevent unauthorized system access"
    )
    severity = Severity.CRITICAL
    requires_root = True

    # systemd rescue service files to check
    RESCUE_SERVICE_PATHS = [
        "/usr/lib/systemd/system/rescue.service",
        "/lib/systemd/system/rescue.service",
        "/etc/systemd/system/rescue.service",
    ]

    # Emergency service files to check
    EMERGENCY_SERVICE_PATHS = [
        "/usr/lib/systemd/system/emergency.service",
        "/lib/systemd/system/emergency.service",
        "/etc/systemd/system/emergency.service",
    ]

    # sulogin paths
    SULOGIN_PATHS = [
        "/usr/sbin/sulogin",
        "/sbin/sulogin",
        "/usr/bin/sulogin",
    ]

    # systemd-sulogin paths
    SYSTEMD_SULOGIN_PATHS = [
        "/usr/lib/systemd/systemd-sulogin",
        "/lib/systemd/systemd-sulogin",
    ]

    def _find_rescue_service(self) -> str | None:
        """Find the rescue.service file.

        Returns:
            Path to the rescue service file, or None if not found
        """
        for path in self.RESCUE_SERVICE_PATHS:
            if os.path.isfile(path):
                return path
        return None

    def _find_emergency_service(self) -> str | None:
        """Find the emergency.service file.

        Returns:
            Path to the emergency service file, or None if not found
        """
        for path in self.EMERGENCY_SERVICE_PATHS:
            if os.path.isfile(path):
                return path
        return None

    def _check_sulogin_exists(self) -> dict:
        """Check if sulogin or systemd-sulogin exists.

        Returns:
            Dictionary with check results
        """
        result = {
            "sulogin_found": False,
            "sulogin_path": None,
            "systemd_sulogin_found": False,
            "systemd_sulogin_path": None,
        }

        for path in self.SULOGIN_PATHS:
            if os.path.isfile(path):
                result["sulogin_found"] = True
                result["sulogin_path"] = path
                break

        for path in self.SYSTEMD_SULOGIN_PATHS:
            if os.path.isfile(path):
                result["systemd_sulogin_found"] = True
                result["systemd_sulogin_path"] = path
                break

        return result

    def _check_service_file(self, file_path: str) -> dict:
        """Check a systemd service file for sulogin configuration.

        Args:
            file_path: Path to the service file

        Returns:
            Dictionary with check results
        """
        result = {
            "file": file_path,
            "exists": False,
            "readable": False,
            "exec_start": None,
            "has_sulogin": False,
            "has_systemd_sulogin": False,
            "has_shell": False,
            "has_bash": False,
            "requires_auth": False,
            "issues": [],
        }

        if not os.path.isfile(file_path):
            result["issues"].append("file does not exist")
            return result

        result["exists"] = True

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                result["readable"] = True

                # Find ExecStart line
                exec_start_pattern = re.compile(
                    r'^\s*ExecStart\s*=\s*(.+)$',
                    re.MULTILINE
                )
                match = exec_start_pattern.search(content)
                if match:
                    exec_start = match.group(1).strip()
                    result["exec_start"] = exec_start

                    # Check for sulogin
                    if "sulogin" in exec_start:
                        result["has_sulogin"] = True
                        result["requires_auth"] = True

                    # Check for systemd-sulogin
                    if "systemd-sulogin" in exec_start:
                        result["has_systemd_sulogin"] = True
                        result["requires_auth"] = True

                    # Check for direct shell access (insecure)
                    if re.search(r'\b(sh|bash|/bin/sh|/bin/bash)\s+-?$', exec_start):
                        result["has_shell"] = True
                        result["has_bash"] = True
                        result["requires_auth"] = False

                else:
                    result["issues"].append("no ExecStart line found")

        except (PermissionError, OSError) as e:
            result["readable"] = False
            result["issues"].append(f"cannot read file: {str(e)}")

        return result

    def _check_sysconfig_init(self) -> dict:
        """Check /etc/sysconfig/init for SINGLE variable (legacy sysvinit).

        Returns:
            Dictionary with check results
        """
        result = {
            "file": "/etc/sysconfig/init",
            "exists": False,
            "readable": False,
            "single_value": None,
            "requires_auth": False,
        }

        if not os.path.isfile(result["file"]):
            return result

        result["exists"] = True

        try:
            with open(result["file"], "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                result["readable"] = True

                # Find SINGLE= line
                single_pattern = re.compile(
                    r'^\s*SINGLE\s*=\s*(.+)$',
                    re.MULTILINE
                )
                match = single_pattern.search(content)
                if match:
                    value = match.group(1).strip().strip('"\'')
                    result["single_value"] = value

                    # /sbin/sulogin requires authentication
                    if "sulogin" in value:
                        result["requires_auth"] = True

        except (PermissionError, OSError):
            result["readable"] = False

        return result

    def _check_init_tab(self) -> dict:
        """Check /etc/inittab for single user mode configuration (legacy).

        Returns:
            Dictionary with check results
        """
        result = {
            "file": "/etc/inittab",
            "exists": False,
            "readable": False,
            "has_sulogin": False,
        }

        if not os.path.isfile(result["file"]):
            return result

        result["exists"] = True

        try:
            with open(result["file"], "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                result["readable"] = True

                # Check for sulogin in single user line
                if re.search(r'^[^#]*:S:.*sulogin', content, re.MULTILINE):
                    result["has_sulogin"] = True

        except (PermissionError, OSError):
            result["readable"] = False

        return result

    def run(self) -> CheckResult:
        """Execute the single-user authentication check.

        Returns:
            CheckResult with the outcome of the check
        """
        # Check if sulogin binary exists
        sulogin_check = self._check_sulogin_exists()

        # Check rescue.service
        rescue_service = self._find_rescue_service()
        rescue_result = None
        if rescue_service:
            rescue_result = self._check_service_file(rescue_service)

        # Check emergency.service
        emergency_service = self._find_emergency_service()
        emergency_result = None
        if emergency_service:
            emergency_result = self._check_service_file(emergency_service)

        # Check legacy configurations
        sysconfig_result = self._check_sysconfig_init()
        inittab_result = self._check_init_tab()

        # Determine if authentication is required
        requires_auth = False
        auth_method = None

        # Check systemd rescue service
        if rescue_result and rescue_result["requires_auth"]:
            requires_auth = True
            if rescue_result["has_systemd_sulogin"]:
                auth_method = "systemd-sulogin"
            elif rescue_result["has_sulogin"]:
                auth_method = "sulogin"

        # Check systemd emergency service
        if emergency_result and emergency_result["requires_auth"]:
            requires_auth = True
            if not auth_method:
                if emergency_result["has_systemd_sulogin"]:
                    auth_method = "systemd-sulogin"
                elif emergency_result["has_sulogin"]:
                    auth_method = "sulogin"

        # Check legacy sysconfig/init
        if sysconfig_result["requires_auth"]:
            requires_auth = True
            auth_method = "sulogin (sysconfig)"

        # Check legacy inittab
        if inittab_result["has_sulogin"]:
            requires_auth = True
            auth_method = "sulogin (inittab)"

        details = {
            "sulogin_check": sulogin_check,
            "rescue_service_path": rescue_service,
            "rescue_result": rescue_result,
            "emergency_service_path": emergency_service,
            "emergency_result": emergency_result,
            "sysconfig_result": sysconfig_result,
            "inittab_result": inittab_result,
            "requires_auth": requires_auth,
            "auth_method": auth_method,
        }

        if requires_auth:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Single-user mode requires authentication ({auth_method})",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Build failure message
        issues = []
        if not sulogin_check["sulogin_found"] and not sulogin_check["systemd_sulogin_found"]:
            issues.append("sulogin binary not found")

        if not rescue_service:
            issues.append("rescue.service not found")
        elif rescue_result and not rescue_result["readable"]:
            issues.append("cannot read rescue.service")
        elif rescue_result and not rescue_result["requires_auth"]:
            issues.append("rescue.service does not require authentication")

        message = "Single-user mode does not require authentication"
        if issues:
            message += f" ({'; '.join(issues)})"

        remediation = """Single-user mode authentication is not configured. To require authentication:

1. Check current rescue.service configuration:
   sudo systemctl cat rescue.service

2. Edit or create /etc/systemd/system/rescue.service.d/auth.conf:
   sudo mkdir -p /etc/systemd/system/rescue.service.d
   sudo nano /etc/systemd/system/rescue.service.d/auth.conf

3. Add the following content:
   [Service]
   ExecStart=
   ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

4. Do the same for emergency.service:
   sudo mkdir -p /etc/systemd/system/emergency.service.d
   sudo nano /etc/systemd/system/emergency.service.d/auth.conf

   [Service]
   ExecStart=
   ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

5. Reload systemd configuration:
   sudo systemctl daemon-reload

6. Verify the configuration:
   sudo systemctl cat rescue.service
   sudo systemctl cat emergency.service

Alternative (older systems):
1. Edit /usr/lib/systemd/system/rescue.service
2. Find the ExecStart line and change it to:
   ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

3. Do the same for emergency.service

Note: Without this protection, anyone with physical access can:
- Boot into single-user mode without a password
- Gain root access to the system
- Modify system files, passwords, or install malware

CIS Benchmark: 1.3.3 - Ensure authentication required for single user mode
"""

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=message,
            remediation=remediation,
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
