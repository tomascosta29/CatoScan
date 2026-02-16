"""
CIS Audit Check: Shell Timeout (5.4.5)

Ensures shell timeout is configured to automatically terminate
idle sessions after 900 seconds (15 minutes) or less.
"""

import os
import re
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class ShellTimeoutCheck(BaseCheck):
    """Check for shell timeout configuration."""

    id = "user_shell_timeout"
    name = "Shell Timeout"
    description = (
        "Verifies that shell timeout is configured to automatically "
        "terminate idle sessions after 900 seconds or less"
    )
    severity = Severity.MEDIUM
    requires_root = True

    # Files to check
    TIMEOUT_FILES = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash.bashrc",
        "/etc/profile.d/*.sh",
    ]
    
    # CIS recommended timeout (seconds)
    MAX_TIMEOUT = 900
    DEFAULT_TIMEOUT = 600  # 10 minutes is a common default

    def _extract_timeout_from_file(self, filepath: str) -> tuple[int | None, str | None]:
        """Extract TMOUT value from a file.

        Args:
            filepath: Path to the file

        Returns:
            Tuple of (timeout_value, line_found) or (None, None)
        """
        path = Path(filepath)
        if not path.exists():
            return None, None

        try:
            with open(path, "r") as f:
                for line in f:
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith("#"):
                        continue

                    # Look for TMOUT setting
                    # Match patterns like: TMOUT=900, export TMOUT=900, readonly TMOUT=900
                    match = re.search(r"(?:^|\s|export\s|readonly\s)TMOUT\s*=\s*(\d+)", line_stripped)
                    if match:
                        try:
                            return int(match.group(1)), line_stripped
                        except ValueError:
                            continue

        except (IOError, OSError):
            pass

        return None, None

    def _check_all_timeout_configs(self) -> dict:
        """Check all configuration files for TMOUT settings.

        Returns:
            Dictionary with findings
        """
        result = {
            "files_checked": [],
            "timeout_settings": [],
            "max_timeout": None,
            "min_timeout": None,
        }

        for pattern in self.TIMEOUT_FILES:
            if "*" in pattern:
                # Handle glob patterns
                import glob
                files = glob.glob(pattern)
                for filepath in sorted(files):
                    timeout, line = self._extract_timeout_from_file(filepath)
                    result["files_checked"].append(filepath)
                    if timeout is not None:
                        result["timeout_settings"].append({
                            "file": filepath,
                            "timeout": timeout,
                            "line": line,
                        })
                        if result["max_timeout"] is None or timeout > result["max_timeout"]:
                            result["max_timeout"] = timeout
                        if result["min_timeout"] is None or timeout < result["min_timeout"]:
                            result["min_timeout"] = timeout
            else:
                timeout, line = self._extract_timeout_from_file(pattern)
                result["files_checked"].append(pattern)
                if timeout is not None:
                    result["timeout_settings"].append({
                        "file": pattern,
                        "timeout": timeout,
                        "line": line,
                    })
                    if result["max_timeout"] is None or timeout > result["max_timeout"]:
                        result["max_timeout"] = timeout
                    if result["min_timeout"] is None or timeout < result["min_timeout"]:
                        result["min_timeout"] = timeout

        return result

    def _check_readonly_export(self) -> dict:
        """Check if TMOUT is exported and made readonly.

        Returns:
            Dictionary with findings
        """
        result = {
            "exported": False,
            "readonly": False,
            "files_with_export": [],
            "files_with_readonly": [],
        }

        for pattern in self.TIMEOUT_FILES:
            if "*" in pattern:
                import glob
                files = glob.glob(pattern)
            else:
                files = [pattern]

            for filepath in files:
                path = Path(filepath)
                if not path.exists():
                    continue

                try:
                    with open(path, "r") as f:
                        content = f.read()
                        
                        # Check for export
                        if re.search(r"export\s+TMOUT", content):
                            result["exported"] = True
                            if filepath not in result["files_with_export"]:
                                result["files_with_export"].append(filepath)
                        
                        # Check for readonly
                        if re.search(r"readonly\s+TMOUT", content):
                            result["readonly"] = True
                            if filepath not in result["files_with_readonly"]:
                                result["files_with_readonly"].append(filepath)

                except (IOError, OSError):
                    pass

        return result

    def run(self) -> CheckResult:
        """Execute the shell timeout check.

        Returns:
            CheckResult with the outcome of the check
        """
        timeout_configs = self._check_all_timeout_configs()
        readonly_info = self._check_readonly_export()

        details = {
            "timeout_configs": timeout_configs,
            "readonly_info": readonly_info,
        }

        # Check if TMOUT is configured at all
        if not timeout_configs["timeout_settings"]:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Shell timeout (TMOUT) is not configured",
                remediation=(
                    "Configure shell timeout in /etc/profile or /etc/bashrc:\n\n"
                    "Add the following lines to /etc/profile:\n"
                    f"TMOUT={self.DEFAULT_TIMEOUT}\n"
                    "readonly TMOUT\n"
                    "export TMOUT\n\n"
                    "This will automatically terminate idle sessions after 10 minutes.\n"
                    f"CIS recommends {self.MAX_TIMEOUT} seconds (15 minutes) or less."
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        issues = []
        recommendations = []

        # Check if timeout exceeds maximum
        max_timeout = timeout_configs["max_timeout"]
        if max_timeout is not None and max_timeout > self.MAX_TIMEOUT:
            issues.append(
                f"Maximum TMOUT is {max_timeout} seconds "
                f"(recommended: {self.MAX_TIMEOUT} or less)"
            )
            recommendations.append(
                f"Set TMOUT to {self.MAX_TIMEOUT} or less in /etc/profile"
            )

        # Check if TMOUT is exported
        if not readonly_info["exported"]:
            issues.append("TMOUT is not exported")
            recommendations.append("Add 'export TMOUT' after setting TMOUT")

        # Check if TMOUT is readonly (best practice)
        if not readonly_info["readonly"]:
            # This is a recommendation, not a strict requirement
            recommendations.append("Consider adding 'readonly TMOUT' to prevent modification")

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Shell timeout issues: {'; '.join(issues)}",
                remediation=(
                    "Fix shell timeout configuration:\n\n"
                    + "\n".join(recommendations)
                    + "\n\nExample /etc/profile configuration:\n"
                    f"TMOUT={min(max_timeout or self.DEFAULT_TIMEOUT, self.MAX_TIMEOUT)}\n"
                    "readonly TMOUT\n"
                    "export TMOUT\n\n"
                    "For more restrictive timeout (5 minutes):\n"
                    "TMOUT=300\n"
                    "readonly TMOUT\n"
                    "export TMOUT"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check passed
        effective_timeout = timeout_configs["max_timeout"]
        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Shell timeout is properly configured (TMOUT={effective_timeout}s)",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
