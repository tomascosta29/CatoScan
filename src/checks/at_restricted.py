"""
CIS Audit Check: At Restricted to Authorized Users (4.1.9)

Ensures that at is restricted to authorized users via at.allow or at.deny.
CIS recommends either:
- /etc/at.allow exists and contains authorized users, OR
- /etc/at.deny does not exist (if using at.allow), OR
- /etc/at.deny exists and is properly restricted
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class AtRestrictedCheck(BaseCheck):
    """Check if at is restricted to authorized users."""

    id = "at_restricted"
    name = "At Restricted to Authorized Users"
    description = (
        "Verifies that at is restricted to authorized users "
        "via /etc/at.allow or /etc/at.deny"
    )
    severity = Severity.MEDIUM
    requires_root = True

    AT_ALLOW = "/etc/at.allow"
    AT_DENY = "/etc/at.deny"

    def _check_restriction(self) -> dict:
        """Check at user restriction configuration.

        Returns:
            Dictionary with restriction check results
        """
        result = {
            "at_allow_exists": False,
            "at_deny_exists": False,
            "restricted": False,
            "method": None,
        }

        allow_path = Path(self.AT_ALLOW)
        deny_path = Path(self.AT_DENY)

        result["at_allow_exists"] = allow_path.exists()
        result["at_deny_exists"] = deny_path.exists()

        # Best practice: at.allow exists (only users in file can use at)
        if result["at_allow_exists"]:
            result["restricted"] = True
            result["method"] = "allow"
            return result

        # Alternative: at.deny exists but is empty or doesn't exist
        # This means all users can use at (not recommended but acceptable)
        if not result["at_deny_exists"]:
            # No restriction files - all users can use at
            result["restricted"] = False
            result["method"] = "none"
            return result

        # at.deny exists but at.allow doesn't
        # This means all users except those in at.deny can use at
        result["restricted"] = True
        result["method"] = "deny"
        return result

    def run(self) -> CheckResult:
        """Execute the at restriction check.

        Returns:
            CheckResult with the outcome of the check
        """
        restriction = self._check_restriction()

        details = {
            "restriction": restriction,
        }

        # CIS recommends at.allow exists (most restrictive)
        if restriction["method"] == "allow":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"At is restricted to authorized users via {self.AT_ALLOW}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # If no restriction files exist, this is a failure
        if restriction["method"] == "none":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="At is not restricted - neither /etc/at.allow nor /etc/at.deny exists",
                remediation=(
                    "Restrict at to authorized users:\n"
                    "\n"
                    "1. Create /etc/at.allow with authorized users:\n"
                    "   sudo touch /etc/at.allow\n"
                    "   sudo chmod 600 /etc/at.allow\n"
                    "   sudo chown root:root /etc/at.allow\n"
                    "\n"
                    "2. Add authorized users to /etc/at.allow (one per line):\n"
                    "   root\n"
                    "   adminuser\n"
                    "\n"
                    "3. Remove /etc/at.deny if it exists:\n"
                    "   sudo rm -f /etc/at.deny\n"
                    "\n"
                    "Note: When /etc/at.allow exists, only users listed in it can use at.\n"
                    "When /etc/at.deny exists (and at.allow doesn't), users listed in it are denied.\n"
                    "\n"
                    "CIS Benchmark: 4.1.9 - Ensure at is restricted to authorized users"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Using at.deny method - acceptable but not best practice
        if restriction["method"] == "deny":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"At is restricted via {self.AT_DENY} (consider using /etc/at.allow for better security)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Should not reach here
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="Unable to determine at restriction status",
            remediation="Check /etc/at.allow and /etc/at.deny manually",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
