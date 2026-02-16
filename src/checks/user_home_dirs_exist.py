"""
CIS Audit Check: Home Directories Exist (6.2.10)

Ensures all users with interactive shells have existing home directories.
Missing home directories can cause issues and may indicate orphaned accounts.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class HomeDirsExistCheck(BaseCheck):
    """Check that all users have existing home directories."""

    id = "user_home_dirs_exist"
    name = "Home Directories Exist"
    description = (
        "Verifies that all users with interactive shells have "
        "existing home directories"
    )
    severity = Severity.MEDIUM
    requires_root = True

    PASSWD_PATH = "/etc/passwd"

    # Shells that indicate interactive users
    INTERACTIVE_SHELLS = [
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/bin/tcsh",
        "/bin/csh",
        "/bin/ksh",
        "/bin/dash",
        "/usr/bin/bash",
        "/usr/bin/sh",
        "/usr/bin/zsh",
        "/usr/bin/tcsh",
        "/usr/bin/csh",
        "/usr/bin/ksh",
        "/usr/bin/dash",
    ]

    # System accounts to exclude
    EXCLUDE_USERS = [
        "root",  # Root is checked separately
        "halt",
        "sync",
        "shutdown",
        "nfsnobody",
    ]

    def _parse_passwd(self) -> list[dict]:
        """Parse /etc/passwd and return interactive user entries.

        Returns:
            List of passwd entries for interactive users
        """
        entries = []
        path = Path(self.PASSWD_PATH)

        if not path.exists():
            return entries

        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) >= 7:
                        username = parts[0]
                        home = parts[5]
                        shell = parts[6]

                        # Skip excluded users
                        if username in self.EXCLUDE_USERS:
                            continue

                        # Skip users with nologin or false shells
                        if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", ""):
                            continue

                        entries.append({
                            "username": username,
                            "home": home,
                            "shell": shell,
                            "is_interactive": shell in self.INTERACTIVE_SHELLS,
                        })
        except (IOError, OSError):
            pass

        return entries

    def run(self) -> CheckResult:
        """Execute the home directories exist check.

        Returns:
            CheckResult with the outcome of the check
        """
        entries = self._parse_passwd()

        if not entries:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.PASSWD_PATH}",
                remediation=f"Verify {self.PASSWD_PATH} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
            )

        # Find users with missing home directories
        missing_homes = []
        for entry in entries:
            home_path = Path(entry["home"])
            if not home_path.exists():
                missing_homes.append(entry)

        if missing_homes:
            usernames = [e["username"] for e in missing_homes]
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(missing_homes)} user(s) with missing home directories: "
                    f"{', '.join(usernames[:10])}"
                    f"{'...' if len(missing_homes) > 10 else ''}"
                ),
                remediation=(
                    "Create missing home directories or fix /etc/passwd entries:\n\n"
                    "To create home directories:\n"
                    "  sudo mkdir -p /home/<username>\n"
                    "  sudo chown <username>:<username> /home/<username>\n"
                    "  sudo chmod 700 /home/<username>\n\n"
                    "To copy skeleton files:\n"
                    "  sudo cp -r /etc/skel/. /home/<username>/\n"
                    "  sudo chown -R <username>:<username> /home/<username>/\n\n"
                    "CIS Benchmark: 6.2.10 - Ensure users' home directories exist"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={"missing_homes": missing_homes},
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"All {len(entries)} users have existing home directories",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"total_users": len(entries)},
        )
