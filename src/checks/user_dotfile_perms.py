"""
CIS Audit Check: Dot File Permissions (6.2.12)

Ensures that dot files in users' home directories (.bashrc, .profile, etc.)
are not writable by group or others.
"""

import stat
from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class DotfilePermissionsCheck(BaseCheck):
    """Check dot file permissions in home directories."""

    id = "user_dotfile_perms"
    name = "Dot File Permissions"
    description = (
        "Verifies that dot files in users' home directories "
        "are not writable by group or others"
    )
    severity = Severity.MEDIUM
    requires_root = True

    PASSWD_PATH = "/etc/passwd"

    # Important dot files to check
    DOTFILES = [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".cshrc",
        ".tcshrc",
        ".zshrc",
        ".zprofile",
        ".login",
        ".logout",
        ".kshrc",
        ".emacs",
        ".vimrc",
        ".exrc",
        ".netrc",
        ".rhosts",
        ".forward",
        ".ssh/config",
        ".ssh/authorized_keys",
        ".ssh/known_hosts",
        ".ssh/id_rsa",
        ".ssh/id_dsa",
        ".ssh/id_ecdsa",
        ".ssh/id_ed25519",
    ]

    # System users to exclude
    EXCLUDE_USERS = [
        "root",
        "halt",
        "sync",
        "shutdown",
        "nfsnobody",
    ]

    def _is_safe_home_path(self, home: str) -> bool:
        """Validate home directory path from passwd.

        Args:
            home: Home path value from /etc/passwd

        Returns:
            True if path is safe and absolute
        """
        if not home:
            return False
        if any(char in home for char in ("\x00", "\n", "\r", "\t")):
            return False

        home_path = Path(home)
        if not home_path.is_absolute():
            return False
        if ".." in home_path.parts:
            return False
        return True

    def _parse_passwd(self) -> tuple[list[dict], list[str]]:
        """Parse /etc/passwd and return user entries with homes.

        Returns:
            Tuple of (passwd entries, parse diagnostics)
        """
        entries = []
        diagnostics: list[str] = []
        path = Path(self.PASSWD_PATH)

        if not path.exists():
            diagnostics.append(f"{self.PASSWD_PATH} not found")
            return entries, diagnostics

        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) >= 6:
                        username = parts[0]
                        home = parts[5]

                        # Skip excluded users
                        if username in self.EXCLUDE_USERS:
                            continue

                        # Skip users with no home or system homes
                        if not home or home in ("/", "/nonexistent", "/var/empty"):
                            continue

                        if not self._is_safe_home_path(home):
                            diagnostics.append(f"Skipped unsafe home path for user '{username}': {home}")
                            continue

                        entries.append({
                            "username": username,
                            "home": home,
                        })
        except (IOError, OSError):
            diagnostics.append(f"Failed to read {self.PASSWD_PATH}")

        return entries, diagnostics

    def _check_dotfile_permissions(self, dotfile_path: Path) -> dict:
        """Check permissions of a dot file.

        Args:
            dotfile_path: Path to the dot file

        Returns:
            Dictionary with check results
        """
        result = {
            "exists": False,
            "is_file": False,
            "mode_ok": False,
            "actual_mode": None,
            "mode_string": None,
        }

        if not dotfile_path.exists():
            return result

        result["exists"] = True

        if not dotfile_path.is_file():
            return result

        result["is_file"] = True

        try:
            st = dotfile_path.stat()
            mode = stat.S_IMODE(st.st_mode)

            result["actual_mode"] = mode
            result["mode_string"] = stat.filemode(st.st_mode)

            # Check if mode is acceptable (no group/other write)
            result["mode_ok"] = (mode & 0o022) == 0

        except (IOError, OSError):
            pass

        return result

    def run(self) -> CheckResult:
        """Execute the dot file permissions check.

        Returns:
            CheckResult with the outcome of the check
        """
        entries, parse_diagnostics = self._parse_passwd()

        if not entries:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Could not read {self.PASSWD_PATH}",
                remediation=f"Verify {self.PASSWD_PATH} exists and is readable",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"diagnostics": parse_diagnostics},
            )

        # Check dot files for each user
        bad_dotfiles = []
        for entry in entries:
            home_path = Path(entry["home"])

            if not home_path.exists() or not home_path.is_dir():
                continue

            for dotfile in self.DOTFILES:
                dotfile_path = home_path / dotfile
                perm_check = self._check_dotfile_permissions(dotfile_path)

                if perm_check["exists"] and perm_check["is_file"] and not perm_check["mode_ok"]:
                    bad_dotfiles.append({
                        "username": entry["username"],
                        "file": str(dotfile_path),
                        "mode": perm_check["mode_string"],
                        "mode_octal": oct(perm_check["actual_mode"]) if perm_check["actual_mode"] else None,
                    })

        if bad_dotfiles:
            files = [f"{d['username']}/{Path(d['file']).name}" for d in bad_dotfiles[:10]]
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=(
                    f"Found {len(bad_dotfiles)} dot file(s) with insecure permissions: "
                    f"{', '.join(files)}"
                    f"{'...' if len(bad_dotfiles) > 10 else ''}"
                ),
                remediation=(
                    "Fix dot file permissions:\n\n"
                    "Remove group and other write permissions:\n"
                    "  sudo chmod go-w /home/<username>/.bashrc\n\n"
                    "For sensitive files (SSH keys, .netrc), use more restrictive permissions:\n"
                    "  sudo chmod 600 /home/<username>/.ssh/id_rsa\n"
                    "  sudo chmod 644 /home/<username>/.ssh/authorized_keys\n"
                    "  sudo chmod 600 /home/<username>/.netrc\n\n"
                    "CIS Benchmark: 6.2.12 - Ensure users' dot files are not group or world writable"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "bad_dotfiles": bad_dotfiles,
                    "diagnostics": parse_diagnostics,
                },
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="All dot files have secure permissions (not group/world writable)",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "total_users": len(entries),
                "dotfiles_checked": self.DOTFILES,
                "diagnostics": parse_diagnostics,
            },
        )
