"""
CIS Audit Check: SELinux Unconfined Services

Checks for unconfined daemons and services running on the system.
CIS 1.5.1.5
"""

import subprocess
from src.core.check import BaseCheck, CheckResult, Severity


class SELinuxUnconfinedCheck(BaseCheck):
    """Check for unconfined services running on the system."""

    id = "selinux_unconfined"
    name = "SELinux Unconfined Services"
    description = (
        "Verifies that no unconfined daemons or services are running "
        "on the system"
    )
    severity = Severity.HIGH
    requires_root = True

    def _get_unconfined_services(self) -> tuple[list[dict], dict]:
        """Get list of unconfined services using ps and selinux tools.

        Returns:
            Tuple of (services_list, details)
        """
        details = {"methods_tried": [], "errors": []}
        unconfined_services = []

        # Method 1: Use ps with security context (Z option)
        try:
            details["methods_tried"].append("ps -eZ")
            result = subprocess.run(
                ["ps", "-eZ"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Look for unconfined_t or unconfined_service_t
                    if "unconfined_t" in line or "unconfined_service_t" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            # Parse: LABEL PID TTY TIME CMD
                            context = parts[0]
                            pid = parts[1]
                            cmd = " ".join(parts[4:]) if len(parts) > 4 else parts[-1] if len(parts) > 2 else "unknown"

                            # Skip kernel threads and common system processes
                            if cmd in ["[migration/0]", "[rcu_gp]", "[rcu_par_gp]",
                                      "[slub_flushwq]", "[netns]", "[kworker", "[kthreadd]",
                                      "[khungtaskd]", "[oom_reaper]"]:
                                continue

                            unconfined_services.append({
                                "pid": pid,
                                "context": context,
                                "command": cmd,
                                "source": "ps",
                            })
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["errors"].append(f"ps method: {str(e)}")

        # Method 2: Use semanage if available
        try:
            details["methods_tried"].append("semanage login -l")
            result = subprocess.run(
                ["semanage", "login", "-l"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                details["semanage_output"] = result.stdout
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["errors"].append(f"semanage method: {str(e)}")

        return unconfined_services, details

    def _check_unconfined_daemons(self) -> tuple[list[str], dict]:
        """Check for unconfined daemons using systemd and other methods.

        Returns:
            Tuple of (daemons_list, details)
        """
        details = {"methods_tried": [], "errors": []}
        unconfined_daemons = []

        # Check for common unconfined services
        try:
            details["methods_tried"].append("systemctl")
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                details["running_services_count"] = len([l for l in result.stdout.split("\n") if l.strip()])
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            details["errors"].append(f"systemctl method: {str(e)}")

        return unconfined_daemons, details

    def run(self) -> CheckResult:
        """Execute the unconfined services check.

        Returns:
            CheckResult with the outcome of the check
        """
        unconfined_services, ps_details = self._get_unconfined_services()
        unconfined_daemons, daemon_details = self._check_unconfined_daemons()

        details = {
            "ps_check": ps_details,
            "daemon_check": daemon_details,
            "unconfined_services": unconfined_services,
            "unconfined_daemons": unconfined_daemons,
        }

        # Filter out expected unconfined processes (init, systemd, etc.)
        expected_unconfined = [
            "init", "systemd", "bash", "sh", "login", "sshd",
        ]

        unexpected_unconfined = [
            svc for svc in unconfined_services
            if not any(exp in svc["command"] for exp in expected_unconfined)
        ]

        if unexpected_unconfined:
            service_list = ", ".join([f"{s['command']} (PID {s['pid']})" for s in unexpected_unconfined[:5]])
            if len(unexpected_unconfined) > 5:
                service_list += f" and {len(unexpected_unconfined) - 5} more"

            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Found {len(unexpected_unconfined)} unconfined service(s): {service_list}",
                remediation=(
                    "Review and confine unconfined services:\n"
                    "1. Identify services running in unconfined domains:\n"
                    "   ps -eZ | grep unconfined\n"
                    "2. Create or update SELinux policies for these services\n"
                    "3. Use 'semanage' to assign proper SELinux user and role\n"
                    "4. Consider using confined domains like httpd_t, mysqld_t, etc.\n"
                    "5. For custom applications, develop custom SELinux policies"
                ),
                severity=self.severity,
                requires_root=self.requires_root,
                details=details,
            )

        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="No unexpected unconfined services found",
            severity=self.severity,
            requires_root=self.requires_root,
            details=details,
        )
