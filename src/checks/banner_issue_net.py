"""
CIS Audit Check: /etc/issue.net Warning Banner (1.6.3)

Ensures that /etc/issue.net is configured with a proper warning banner
that does not contain OS or version information.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class BannerIssueNetCheck(BaseCheck):
    """Check /etc/issue.net warning banner configuration."""

    id = "banner_issue_net"
    name = "/etc/issue.net Warning Banner"
    description = (
        "Verifies that /etc/issue.net is configured with a proper warning banner "
        "and does not contain OS or version information"
    )
    severity = Severity.MEDIUM
    requires_root = True

    FILE_PATH = "/etc/issue.net"

    # Patterns that indicate OS/version information
    OS_VERSION_PATTERNS = [
        r'fedora', r'red\s*hat', r'rhel', r'centos',
        r'ubuntu', r'debian', r'suse', r'opensuse',
        r'linux', r'kernel', r'\b\d+\.\d+\.\d+',  # version numbers like 1.2.3
        r'\bversion\s*\d+', r'release\s*\d+',
    ]

    def _check_banner_content(self) -> dict:
        """Check the banner file content.

        Returns:
            Dictionary with check results
        """
        result = {
            "path": self.FILE_PATH,
            "exists": False,
            "readable": False,
            "has_content": False,
            "contains_os_info": False,
            "content": None,
            "os_info_matches": [],
        }

        path = Path(self.FILE_PATH)
        if not path.exists():
            return result

        result["exists"] = True

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result["readable"] = True
            result["content"] = content

            # Check if file has content (non-empty)
            result["has_content"] = len(content.strip()) > 0

            # Check for OS/version information
            content_lower = content.lower()
            for pattern in self.OS_VERSION_PATTERNS:
                matches = re.findall(pattern, content_lower, re.IGNORECASE)
                if matches:
                    result["contains_os_info"] = True
                    result["os_info_matches"].extend(matches)

        except (IOError, OSError) as e:
            result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the /etc/issue.net banner check.

        Returns:
            CheckResult with the outcome of the check
        """
        check_result = self._check_banner_content()

        if not check_result["exists"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.FILE_PATH} does not exist",
                remediation=f"Create {self.FILE_PATH} with a warning banner",
                severity=self.severity,
                requires_root=self.requires_root,
                details=check_result,
            )

        if not check_result["readable"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cannot read {self.FILE_PATH}",
                remediation=f"Check file permissions for {self.FILE_PATH}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=check_result,
            )

        if not check_result["has_content"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.FILE_PATH} is empty",
                remediation=f"Add a warning banner to {self.FILE_PATH}",
                severity=self.severity,
                requires_root=self.requires_root,
                details=check_result,
            )

        if check_result["contains_os_info"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"{self.FILE_PATH} contains OS/version information",
                remediation=(
                    f"Edit {self.FILE_PATH} to remove OS/version information:\n"
                    f"  sudo nano {self.FILE_PATH}\n\n"
                    f"Remove references to: {', '.join(set(check_result['os_info_matches']))}\n\n"
                    f"Example warning banner:\n"
                    f"  Authorized uses only. All activity may be monitored and reported.\n\n"
                    f"CIS Benchmark: 1.6.3 - Ensure remote login warning banner is configured properly"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=check_result,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"{self.FILE_PATH} has a proper warning banner without OS/version information",
            severity=self.severity,
            requires_root=self.requires_root,
            details=check_result,
        )
