"""
CIS Audit Check: /etc/shadow Permissions (6.1.5)

Ensures that /etc/shadow is owned by root and has appropriate permissions.
CIS recommends 000 (---------) or more restrictive, but typically 600 is acceptable.
"""

import os
import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class ShadowPermissionsCheck(BaseCheck):
    """Check /etc/shadow file permissions."""

    id = "perm_shadow"
    name = "/etc/shadow Permissions"
    description = (
        "Verifies that /etc/shadow is owned by root:root "
        "and has permissions 000/600 or more restrictive"
    )
    severity = Severity.MEDIUM
    requires_root = True

    FILE_PATH = "/etc/shadow"
    EXPECTED_MODE = 0o600  # Some systems use 000, but 600 is acceptable
    EXPECTED_OWNER = 0  # root
    EXPECTED_GROUP = 0  # root

    def _check_permissions(self) -> dict:
        """Check file permissions and ownership.

        Returns:
            Dictionary with check results
        """
        result = {
            "path": self.FILE_PATH,
            "exists": False,
            "mode_ok": False,
            "owner_ok": False,
            "group_ok": False,
            "actual_mode": None,
            "actual_owner": None,
            "actual_group": None,
            "mode_string": None,
        }

        path = Path(self.FILE_PATH)
        if not path.exists():
            return result

        result["exists"] = True

        try:
            st = path.stat()
            result["actual_mode"] = stat.S_IMODE(st.st_mode)
            result["actual_owner"] = st.st_uid
            result["actual_group"] = st.st_gid
            result["mode_string"] = stat.filemode(st.st_mode)

            # Check mode (should be 600 or more restrictive, ideally 000)
            # Allow both 000 and 600 as acceptable
            result["mode_ok"] = result["actual_mode"] <= self.EXPECTED_MODE

            # Check owner (should be root)
            result["owner_ok"] = st.st_uid == self.EXPECTED_OWNER

            # Check group (should be root)
            result["group_ok"] = st.st_gid == self.EXPECTED_GROUP

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the /etc/shadow permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        check_result = self._check_permissions()

        if not check_result["exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.FILE_PATH} does not exist",
                remediation=f"Restore {self.FILE_PATH} from backup or reinstall shadow-utils",
                severity=self.severity,
                requires_root=self.requires_root,
                details=check_result,
            )

        issues = []
        if not check_result["mode_ok"]:
            issues.append(
                f"permissions are {oct(check_result['actual_mode'])} "
                f"(expected {oct(self.EXPECTED_MODE)} or more restrictive)"
            )
        if not check_result["owner_ok"]:
            issues.append(f"owner is UID {check_result['actual_owner']} (expected root)")
        if not check_result["group_ok"]:
            issues.append(f"group is GID {check_result['actual_group']} (expected root)")

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.FILE_PATH}: {', '.join(issues)}",
                remediation=(
                    f"Fix {self.FILE_PATH} permissions:\n"
                    f"  sudo chown root:root {self.FILE_PATH}\n"
                    f"  sudo chmod 600 {self.FILE_PATH}\n\n"
                    f"CIS Benchmark: 6.1.5 - Ensure permissions on /etc/shadow are configured"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=check_result,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=(
                f"{self.FILE_PATH} has correct permissions: "
                f"{check_result['mode_string']}, owned by root:root"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=check_result,
        )
