"""
CIS Audit Check: Journald Compresses Large Logs (4.2.2.2)

Ensures systemd-journald is configured to compress large log files.
"""

from pathlib import Path

from src.core.check import BaseCheck, CheckResult, Severity


class JournaldCompressCheck(BaseCheck):
    """Check if journald is configured to compress large logs."""

    id = "journald_compress"
    name = "Journald Compresses Large Logs"
    description = (
        "Verifies that systemd-journald is configured to compress large log files "
        "to save disk space"
    )
    severity = Severity.MEDIUM
    requires_root = True

    CONFIG_PATH = "/etc/systemd/journald.conf"

    def _read_journald_config(self) -> dict:
        """Read journald configuration file.

        Returns:
            Dictionary with configuration settings
        """
        result = {
            "config_exists": False,
            "config_path": self.CONFIG_PATH,
            "compress": None,
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
                        
                        # Parse Compress setting
                        if line.startswith("Compress="):
                            value = line.split("=", 1)[1].strip()
                            result["compress"] = value.lower()
                            
            except (PermissionError, OSError) as e:
                result["error"] = str(e)

        return result

    def run(self) -> CheckResult:
        """Execute the journald compress check.

        Returns:
            CheckResult with the outcome of the check
        """
        config = self._read_journald_config()

        details = {
            "config": config,
        }

        # Check if config file exists
        if not config["config_exists"]:
            # Default behavior: journald compresses by default
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald.conf not found, using defaults (Compress=yes by default)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        compress_value = config.get("compress")

        # If not explicitly set, default is "yes"
        if compress_value is None:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Compress not explicitly set, using default (yes)",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        if compress_value == "yes":
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="journald is configured to compress large log files",
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"journald Compress is set to '{compress_value}' (expected: yes)",
            remediation=(
                "Configure journald to compress large logs:\n"
                "1. Edit /etc/systemd/journald.conf:\n"
                "   sudo nano /etc/systemd/journald.conf\n"
                "2. Add or modify in the [Journal] section:\n"
                "   Compress=yes\n"
                "3. Restart journald:\n"
                "   sudo systemctl restart systemd-journald\n"
                "4. Verify compression is active:\n"
                "   sudo journalctl --disk-usage"
            ),
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
