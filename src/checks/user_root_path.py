"""
CIS Audit Check: Root PATH Integrity (6.2.8)

Ensures root's PATH environment variable does not contain
relative paths (., ..) or writable directories that could
lead to privilege escalation.
"""

import os
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class RootPathCheck(BaseCheck):
    """Check root's PATH integrity."""

    id = "user_root_path"
    name = "Root PATH Integrity"
    description = (
        "Verifies that root's PATH does not contain relative paths "
        "or world-writable directories"
    )
    severity = Severity.MEDIUM
    requires_root = True

    def _get_root_path(self) -> str:
        """Get root's PATH from /root/.bashrc, /root/.bash_profile, or /etc/profile.

        Returns:
            PATH string or empty if not found
        """
        # Check common locations for root's PATH
        files_to_check = [
            "/root/.bash_profile",
            "/root/.bashrc",
            "/root/.profile",
            "/etc/profile",
            "/etc/profile.d/*.sh",
        ]

        path_value = ""

        # First try to get from current environment (if running as root)
        if os.geteuid() == 0:
            path_value = os.environ.get("PATH", "")

        # If not available, check files
        if not path_value:
            for filepath in files_to_check:
                if "*" in filepath:
                    # Handle glob patterns
                    import glob
                    for f in glob.glob(filepath):
                        path_value = self._extract_path_from_file(f)
                        if path_value:
                            break
                else:
                    path_value = self._extract_path_from_file(filepath)

                if path_value:
                    break

        return path_value

    def _extract_path_from_file(self, filepath: str) -> str:
        """Extract PATH value from a file.

        Args:
            filepath: Path to the file

        Returns:
            PATH value or empty string
        """
        path = Path(filepath)
        if not path.exists():
            return ""

        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("export PATH=") or line.startswith("PATH="):
                        # Extract the value
                        if "=" in line:
                            value = line.split("=", 1)[1]
                            # Remove quotes if present
                            value = value.strip('"\'')
                            # Remove 'export ' prefix if present
                            value = value.replace("export ", "")
                            return value
        except (IOError, OSError):
            pass

        return ""

    def _check_path_issues(self, path_value: str) -> tuple[list[str], list[str]]:
        """Check PATH for security issues.

        Args:
            path_value: The PATH string to check

        Returns:
            Tuple of (issues list, path entries)
        """
        issues = []
        entries = path_value.split(":") if path_value else []

        for entry in entries:
            if not entry:
                continue

            # Check for relative paths
            if entry in (".", "..") or entry.startswith("./") or entry.startswith("../"):
                issues.append(f"Relative path found: {entry}")
                continue

            # Check if directory is world-writable
            try:
                p = Path(entry)
                if p.exists() and p.is_dir():
                    mode = p.stat().st_mode
                    # Check if world-writable (0o002)
                    if mode & 0o002:
                        issues.append(f"World-writable directory: {entry}")
            except (IOError, OSError, PermissionError):
                # Can't check, skip
                pass

        return issues, entries

    def run(self) -> CheckResult:
        """Execute the root PATH integrity check.

        Returns:
            CheckResult with the outcome of the check
        """
        path_value = self._get_root_path()

        if not path_value:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Could not determine root's PATH",
                remediation=(
                    "Verify root's PATH is set in /root/.bash_profile or /root/.bashrc\n"
                    "Add: export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
            )

        issues, entries = self._check_path_issues(path_value)

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(issues)} issue(s) in root's PATH: "
                    f"{'; '.join(issues[:5])}"
                    f"{'...' if len(issues) > 5 else ''}"
                ),
                remediation=(
                    "Fix root's PATH in /root/.bash_profile or /root/.bashrc:\n"
                    "  - Remove relative paths (., .., ./, ../)\n"
                    "  - Remove world-writable directories\n"
                    "  - Use absolute paths only\n\n"
                    "Recommended PATH:\n"
                    "  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
                    "CIS Benchmark: 6.2.8 - Ensure root PATH Integrity"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"path": path_value, "entries": entries, "issues": issues},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Root's PATH is secure with {len(entries)} absolute path entries",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"path": path_value, "entries": entries},
        )
