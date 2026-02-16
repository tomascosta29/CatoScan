"""
CIS Audit Check: Group Consistency (6.2.3)

Ensures all groups in /etc/group have consistent GIDs and valid entries.
Checks for legacy '+' entries and malformed lines.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class GroupConsistencyCheck(BaseCheck):
    """Check group file consistency."""

    id = "user_group_consistency"
    name = "Group Consistency"
    description = (
        "Verifies that /etc/group has consistent entries, "
        "no legacy '+' entries, and valid GIDs"
    )
    severity = Severity.MEDIUM
    requires_root = True

    GROUP_PATH = "/etc/group"

    def _parse_group(self) -> tuple[list[dict], list[str]]:
        """Parse /etc/group and return entries with any parsing issues.

        Returns:
            Tuple of (valid entries, issue list)
        """
        entries = []
        issues = []
        path = Path(self.GROUP_PATH)

        if not path.exists():
            return entries, ["File does not exist"]

        try:
            with open(path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Check for legacy '+' entries
                    if line.startswith("+"):
                        issues.append(f"Line {line_num}: Legacy '+' entry found")
                        continue

                    parts = line.split(":")
                    if len(parts) != 4:
                        issues.append(f"Line {line_num}: Malformed entry (expected 4 fields, got {len(parts)})")
                        continue

                    groupname, password, gid, members = parts

                    # Validate GID is numeric
                    try:
                        gid_num = int(gid)
                    except ValueError:
                        issues.append(f"Line {line_num}: Non-numeric GID '{gid}' for group '{groupname}'")
                        continue

                    entries.append({
                        "groupname": groupname,
                        "gid": gid_num,
                        "members": members.split(",") if members else [],
                    })

        except (IOError, OSError) as e:
            issues.append(f"Error reading file: {e}")

        return entries, issues

    def run(self) -> CheckResult:
        """Execute the group consistency check.

        Returns:
            CheckResult with the outcome of the check
        """
        entries, issues = self._parse_group()

        if not entries and not issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.GROUP_PATH}",
                remediation=f"Verify {self.GROUP_PATH} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
            )

        if issues:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(issues)} issue(s) in /etc/group: "
                    f"{'; '.join(issues[:5])}"
                    f"{'...' if len(issues) > 5 else ''}"
                ),
                remediation=(
                    "Fix issues in /etc/group:\n"
                    "  - Remove legacy '+' entries (NIS compatibility)\n"
                    "  - Ensure all entries have 4 colon-separated fields\n"
                    "  - Ensure GIDs are numeric\n\n"
                    "CIS Benchmark: 6.2.3 - Ensure no legacy '+' entries exist in /etc/group"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"issues": issues, "valid_entries": len(entries)},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} group entries are consistent and valid",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_groups": len(entries)},
        )
