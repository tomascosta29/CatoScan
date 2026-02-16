"""
CIS Audit Check: Journald Writes to Persistent Disk (4.2.2.3)

Ensures systemd-journald is configured to write logs to persistent disk.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class JournaldPersistentCheck(BaseCheck):
    """Check if journald is configured to write logs to persistent disk."""

    id = "journald_persistent"
    name = "Journald Writes to Persistent Disk"
    description = (
        "Verifies that systemd-journald is configured to store logs persistently "
        "on disk rather than only in volatile memory"
    )
    severity = Severity.MEDIUM
    requires_root = True

    CONFIG_PATH = "/etc/systemd/journald.conf"
    STORAGE_PATH = "/var/log/journal"

    def _read_journald_config(self) -> dict:
        """Read journald configuration file.

        Returns:
            Dictionary with configuration settings
        """
        result = {
            "config_exists": False,
            "config_path": self.CONFIG_PATH,
            "storage": None,
            "config_lines": [],
        }

        config_file = Path(self.CONFIG_PATH)
        if config_file.exists():
            result["config_exists"] = True
            try:
                with open(config_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        result["config_lines"].append(line)
                        
                        if not line or line.startswith("#"):
                            continue
                        
                        # Parse Storage setting
                        if line.startswith("Storage="):
                            value = line.split("=", 1)[1].strip()
                            result["storage"] = value.lower()
                            
            except (PermissionError, OSError) as e:
                result["error"] = str(e)

        return result

    def _check_persistent_storage(self) -> dict:
        """Check if persistent journal storage directory exists.

        Returns:
            Dictionary with storage status
        """
        result = {
            "storage_dir_exists": False,
            "storage_dir_path": self.STORAGE_PATH,
        }

        storage_dir = Path(self.STORAGE_PATH)
        result["storage_dir_exists"] = storage_dir.exists() and storage_dir.is_dir()

        return result

    def run(self) -> CheckResult:
        """Execute the journald persistent storage check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_journald_config()
        storage = self._check_persistent_storage()

        details = {
            "config": config,
            "storage": storage,
        }

        storage_value = config.get("storage")
        storage_dir_exists = storage["storage_dir_exists"]

        # Check if explicitly set to persistent
        if storage_value == "persistent":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald is configured with Storage=persistent",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Check if explicitly set to auto and directory exists
        if storage_value == "auto" and storage_dir_exists:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald Storage=auto and /var/log/journal exists",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # If not set, default is "auto" - check if directory exists
        if storage_value is None and storage_dir_exists:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald using default Storage=auto and /var/log/journal exists",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Failed cases
        if storage_value == "volatile":
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald Storage is set to 'volatile' (logs will not persist across reboots)",
                remediation=(
                    "Configure journald for persistent storage:\n"
                    "1. Create the journal directory:\n"
                    "   sudo mkdir -p /var/log/journal\n"
                    "2. Set appropriate permissions:\n"
                    "   sudo systemd-tmpfiles --create --prefix /var/log/journal\n"
                    "3. Edit /etc/systemd/journald.conf:\n"
                    "   sudo nano /etc/systemd/journald.conf\n"
                    "4. Add or modify in the [Journal] section:\n"
                    "   Storage=persistent\n"
                    "5. Restart journald:\n"
                    "   sudo systemctl restart systemd-journald\n"
                    "6. Verify persistent storage:\n"
                    "   sudo journalctl --disk-usage"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if storage_value == "auto" and not storage_dir_exists:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald Storage=auto but /var/log/journal directory does not exist",
                remediation=(
                    "Create persistent journal storage directory:\n"
                    "1. Create the journal directory:\n"
                    "   sudo mkdir -p /var/log/journal\n"
                    "2. Set appropriate permissions:\n"
                    "   sudo systemd-tmpfiles --create --prefix /var/log/journal\n"
                    "3. Restart journald:\n"
                    "   sudo systemctl restart systemd-journald\n"
                    "4. Verify persistent storage:\n"
                    "   sudo journalctl --disk-usage\n"
                    "   sudo ls -la /var/log/journal/"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        # Default case - no config and no directory
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="journald is not configured for persistent storage (default: auto, /var/log/journal does not exist)",
            remediation=(
                "Configure journald for persistent storage:\n"
                "1. Create the journal directory:\n"
                "   sudo mkdir -p /var/log/journal\n"
                "2. Set appropriate permissions:\n"
                "   sudo systemd-tmpfiles --create --prefix /var/log/journal\n"
                "3. (Optional) Explicitly set Storage=persistent in /etc/systemd/journald.conf:\n"
                "   sudo nano /etc/systemd/journald.conf\n"
                "   Add: Storage=persistent\n"
                "4. Restart journald:\n"
                "   sudo systemctl restart systemd-journald\n"
                "5. Verify persistent storage:\n"
                "   sudo journalctl --disk-usage"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
