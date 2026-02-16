"""
CIS Audit Check: Unique Group Names (6.2.7)

Ensures all entries in /etc/group have unique group names.
Duplicate group names can cause permission and access control issues.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class UniqueGroupNameCheck(BaseCheck):
    """Check that all group names are unique."""

    id = "user_unique_group_name"
    name = "Unique Group Names"
    description = (
        "Verifies that all entries in /etc/group have unique group names"
    )
    severity = Severity.MEDIUM
    requires_root = True

    GROUP_PATH = "/etc/group"

    def _parse_group(self) -> list[dict]:
        """Parse /etc/group and return entries.

        Returns:
            List of group entries
        """
        entries = []
        path = Path(self.GROUP_PATH)

        if not path.exists():
            return entries

        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) >= 1:
                        entries.append({
                            "groupname": parts[0],
                        })
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the unique group name check.

        Returns:
            CheckResult with the outcome of the check
        """
        entries = self._parse_group()

        if not entries:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.GROUP_PATH}",
                remediation=f"Verify {self.GROUP_PATH} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
            )

        # Find duplicate group names
        groupname_counts: dict[str, int] = {}
        for entry in entries:
            groupname = entry["groupname"]
            groupname_counts[groupname] = groupname_counts.get(groupname, 0) + 1

        duplicates = {name: count for name, count in groupname_counts.items() if count > 1}

        if duplicates:
            dup_str = ", ".join(f"{name} ({count} times)" for name, count in list(duplicates.items())[:5])
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Found duplicate group names: {dup_str}",
                remediation=(
                    "Remove or rename duplicate group entries in /etc/group:\n"
                    "  sudo groupmod -n <new_name> <old_name>\n"
                    "  OR manually edit /etc/group (with caution)\n\n"
                    "CIS Benchmark: 6.2.7 - Ensure no duplicate group names exist"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"duplicates": duplicates},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} entries have unique group names",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_groups": len(entries)},
        )
