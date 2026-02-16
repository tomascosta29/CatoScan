"""
CIS Audit Check: Unique GIDs (6.2.5)

Ensures all groups in /etc/group have unique GIDs.
Duplicate GIDs can lead to security issues and permission confusion.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class UniqueGIDCheck(BaseCheck):
    """Check that all GIDs are unique."""

    id = "user_unique_gid"
    name = "Unique GIDs"
    description = (
        "Verifies that all groups in /etc/group have unique GIDs"
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
                    if len(parts) >= 3:
                        try:
                            gid = int(parts[2])
                            entries.append({
                                "groupname": parts[0],
                                "gid": gid,
                            })
                        except ValueError:
                            pass
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the unique GID check.

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

        # Find duplicate GIDs
        gid_to_groups: dict[int, list[str]] = {}
        for entry in entries:
            gid = entry["gid"]
            if gid not in gid_to_groups:
                gid_to_groups[gid] = []
            gid_to_groups[gid].append(entry["groupname"])

        duplicates = {gid: groups for gid, groups in gid_to_groups.items() if len(groups) > 1}

        if duplicates:
            dup_str = ", ".join(
                f"GID {gid}: {', '.join(groups)}"
                for gid, groups in list(duplicates.items())[:5]
            )
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Found duplicate GIDs: {dup_str}",
                remediation=(
                    "Assign unique GIDs to each group:\n"
                    "  sudo groupmod -g <new_gid> <groupname>\n\n"
                    "Note: Changing GIDs may require updating file group ownership.\n\n"
                    "CIS Benchmark: 6.2.5 - Ensure no duplicate GIDs exist"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"duplicates": duplicates},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} groups have unique GIDs",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_groups": len(entries)},
        )
