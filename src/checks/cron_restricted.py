"""
CIS Audit Check: Cron Restricted to Authorized Users (4.1.8)

Ensures that cron is restricted to authorized users via cron.allow or cron.deny.
CIS recommends either:
- /etc/cron.allow exists and contains authorized users, OR
- /etc/cron.deny does not exist (if using cron.allow), OR
- /etc/cron.deny exists and is properly restricted
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class CronRestrictedCheck(BaseCheck):
    """Check if cron is restricted to authorized users."""

    id = "cron_restricted"
    name = "Cron Restricted to Authorized Users"
    description = (
        "Verifies that cron is restricted to authorized users "
        "via /etc/cron.allow or /etc/cron.deny"
    )
    severity = Severity.MEDIUM
    requires_root = True

    CRON_ALLOW = "/etc/cron.allow"
    CRON_DENY = "/etc/cron.deny"

    def _check_restriction(self) -> dict:
        """Check cron user restriction configuration.

        Returns:
            Dictionary with restriction check results
        """
        result = {
            "cron_allow_exists": False,
            "cron_deny_exists": False,
            "restricted": False,
            "method": None,
        }

        allow_path = Path(self.CRON_ALLOW)
        deny_path = Path(self.CRON_DENY)

        result["cron_allow_exists"] = allow_path.exists()
        result["cron_deny_exists"] = deny_path.exists()

        # Best practice: cron.allow exists (only users in file can use cron)
        if result["cron_allow_exists"]:
            result["restricted"] = True
            result["method"] = "allow"
            return result

        # Alternative: cron.deny exists but is empty or doesn't exist
        # This means all users can use cron (not recommended but acceptable)
        if not result["cron_deny_exists"]:
            # No restriction files - all users can use cron
            result["restricted"] = False
            result["method"] = "none"
            return result

        # cron.deny exists but cron.allow doesn't
        # This means all users except those in cron.deny can use cron
        result["restricted"] = True
        result["method"] = "deny"
        return result

    def run(self) -> CheckResult:
        """Execute the cron restriction check.

        Returns:
            CheckResult with the outcome of the check
        """
        restriction = self._check_restriction()

        details = {
            "restriction": restriction,
        }

        # CIS recommends cron.allow exists (most restrictive)
        if restriction["method"] == "allow":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cron is restricted to authorized users via {self.CRON_ALLOW}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # If no restriction files exist, this is a failure
        if restriction["method"] == "none":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Cron is not restricted - neither /etc/cron.allow nor /etc/cron.deny exists",
                remediation=(
                    "Restrict cron to authorized users:\n"
                    "\n"
                    "1. Create /etc/cron.allow with authorized users:\n"
                    "   sudo touch /etc/cron.allow\n"
                    "   sudo chmod 600 /etc/cron.allow\n"
                    "   sudo chown root:root /etc/cron.allow\n"
                    "\n"
                    "2. Add authorized users to /etc/cron.allow (one per line):\n"
                    "   root\n"
                    "   adminuser\n"
                    "\n"
                    "3. Remove /etc/cron.deny if it exists:\n"
                    "   sudo rm -f /etc/cron.deny\n"
                    "\n"
                    "Note: When /etc/cron.allow exists, only users listed in it can use cron.\n"
                    "When /etc/cron.deny exists (and cron.allow doesn't), users listed in it are denied.\n"
                    "\n"
                    "CIS Benchmark: 4.1.8 - Ensure cron is restricted to authorized users"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Using cron.deny method - acceptable but not best practice
        if restriction["method"] == "deny":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cron is restricted via {self.CRON_DENY} (consider using /etc/cron.allow for better security)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Should not reach here
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="Unable to determine cron restriction status",
            remediation="Check /etc/cron.allow and /etc/cron.deny manually",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
