"""
CIS Audit Tool for Fedora 43 - Base Check Class

This module provides the abstract base class for all CIS checks
and the CheckResult dataclass for storing check results.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .platform import PlatformContext


class Severity(Enum):
    """Severity levels for CIS checks.
    
    Attributes:
        CRITICAL: Critical security issue requiring immediate attention
        HIGH: High priority security issue
        MEDIUM: Medium priority security recommendation
        LOW: Low priority informational finding
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CheckResult:
    """Result of a CIS check execution.
    
    Attributes:
        check_id: Unique identifier for the check
        check_name: Human-readable name of the check
        passed: True if the check passed, False if it failed
        skipped: True if the check was skipped (e.g., no privileges)
        message: Explanation of the result
        remediation: Instructions on how to fix if failed
        severity: Severity level of the check
        requires_root: Whether the check requires root privileges
        details: Optional additional details (e.g., file paths, values found)
    """
    check_id: str
    check_name: str
    passed: bool
    skipped: bool = False
    message: str = ""
    remediation: str = ""
    severity: Severity = Severity.MEDIUM
    requires_root: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Validate the result after initialization."""
        if not self.check_id:
            raise ValueError("check_id cannot be empty")
        if not self.check_name:
            raise ValueError("check_name cannot be empty")
        if self.skipped and self.passed:
            raise ValueError("A skipped check cannot be marked as passed")
    
    def to_dict(self) -> dict[str, Any]:
        """Convert the result to a dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of the check result
        """
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "passed": self.passed,
            "skipped": self.skipped,
            "message": self.message,
            "remediation": self.remediation,
            "severity": self.severity.value,
            "requires_root": self.requires_root,
            "details": self.details,
        }
    
    @classmethod
    def passed_result(
        cls,
        check_id: str,
        check_name: str,
        message: str = "Check passed",
        severity: Severity = Severity.MEDIUM,
        requires_root: bool = False,
        details: Optional[dict[str, Any]] = None
    ) -> "CheckResult":
        """Create a passed check result.
        
        Args:
            check_id: Unique identifier for the check
            check_name: Human-readable name of the check
            message: Explanation of the result
            severity: Severity level of the check
            requires_root: Whether the check requires root privileges
            details: Optional additional details
            
        Returns:
            CheckResult with passed=True
        """
        return cls(
            check_id=check_id,
            check_name=check_name,
            passed=True,
            skipped=False,
            message=message,
            remediation="",
            severity=severity,
            requires_root=requires_root,
            details=details or {},
        )
    
    @classmethod
    def failed_result(
        cls,
        check_id: str,
        check_name: str,
        message: str = "Check failed",
        remediation: str = "",
        severity: Severity = Severity.MEDIUM,
        requires_root: bool = False,
        details: Optional[dict[str, Any]] = None
    ) -> "CheckResult":
        """Create a failed check result.
        
        Args:
            check_id: Unique identifier for the check
            check_name: Human-readable name of the check
            message: Explanation of the failure
            remediation: Instructions on how to fix
            severity: Severity level of the check
            requires_root: Whether the check requires root privileges
            details: Optional additional details
            
        Returns:
            CheckResult with passed=False
        """
        return cls(
            check_id=check_id,
            check_name=check_name,
            passed=False,
            skipped=False,
            message=message,
            remediation=remediation,
            severity=severity,
            requires_root=requires_root,
            details=details or {},
        )
    
    @classmethod
    def skipped_result(
        cls,
        check_id: str,
        check_name: str,
        message: str = "Check skipped - insufficient privileges",
        severity: Severity = Severity.MEDIUM,
        requires_root: bool = False,
        details: Optional[dict[str, Any]] = None
    ) -> "CheckResult":
        """Create a skipped check result.
        
        Args:
            check_id: Unique identifier for the check
            check_name: Human-readable name of the check
            message: Explanation of why the check was skipped
            severity: Severity level of the check
            requires_root: Whether the check requires root privileges
            details: Optional additional details
            
        Returns:
            CheckResult with skipped=True
        """
        return cls(
            check_id=check_id,
            check_name=check_name,
            passed=False,
            skipped=True,
            message=message,
            remediation="Run with sudo/root privileges to execute this check",
            severity=severity,
            requires_root=requires_root,
            details=details or {},
        )


class BaseCheck(ABC):
    """Abstract base class for all CIS checks.
    
    All CIS checks must inherit from this class and implement
    the required attributes and the run() method.
    
    Example:
        class PasswordComplexityCheck(BaseCheck):
            id = "auth_password_complexity"
            name = "Password Complexity Requirements"
            description = "Checks if password complexity requirements are configured"
            severity = Severity.HIGH
            requires_root = True
            expensive = False
            optional = False
            
            def run(self) -> CheckResult:
                # Check implementation
                if self._check_pam_config():
                    return CheckResult.passed_result(
                        check_id=self.id,
                        check_name=self.name,
                        message="Password complexity is properly configured"
                    )
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Password complexity is not configured",
                    remediation="Install and configure pam_pwquality"
                )
    """
    
    # Check metadata - must be overridden by subclasses
    id: str = ""  # Unique identifier (e.g., "auth_password_complexity")
    name: str = ""  # Human-readable name
    description: str = ""  # What this check does
    severity: Severity = Severity.MEDIUM  # Severity level
    requires_root: bool = False  # Whether root privileges are required
    expensive: bool = False  # Whether check is resource-intensive (skipped by default)
    optional: bool = False  # Whether check is optional (skipped by default)
    
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate that subclasses define required attributes."""
        super().__init_subclass__(**kwargs)
        
        # Validate required attributes are set
        if not cls.id:
            raise ValueError(f"Check class {cls.__name__} must define 'id'")
        if not cls.name:
            raise ValueError(f"Check class {cls.__name__} must define 'name'")
        if not cls.description:
            raise ValueError(f"Check class {cls.__name__} must define 'description'")
        
        # Validate id format (lowercase with underscores)
        if not cls.id.replace("_", "").isalnum() or not cls.id.islower():
            raise ValueError(
                f"Check id '{cls.id}' must be lowercase alphanumeric with underscores only"
            )
    
    def __init__(
        self,
        privileged: bool = False,
        platform_context: Optional["PlatformContext"] = None,
    ) -> None:
        """Initialize the check.
        
        Args:
            privileged: Whether the check is running with root privileges
            platform_context: Platform context with distro-specific adapters
        """
        self._privileged = privileged
        self._platform_context = platform_context
    
    @property
    def privileged(self) -> bool:
        """Check if running with root privileges."""
        return self._privileged

    @property
    def platform_context(self) -> "PlatformContext":
        """Get the current platform context.

        Returns:
            PlatformContext with distro-specific behavior and metadata
        """
        if self._platform_context is None:
            from .platform import get_platform_context

            self._platform_context = get_platform_context()
        return self._platform_context

    def _platform_package_installed(self, package: str) -> bool:
        """Check package installation via platform adapter.

        Args:
            package: Package name or logical package key

        Returns:
            True if package is installed, False otherwise
        """
        installed, _ = self.platform_context.check_package_installed(package)
        return installed

    def _platform_service_status(self, service: str) -> dict[str, Any]:
        """Check service status via platform adapter.

        Args:
            service: Service unit name (without suffix)

        Returns:
            Dictionary with installed/active/enabled booleans and raw statuses
        """
        active, active_status = self.platform_context.check_service_active(service)
        enabled, enabled_status = self.platform_context.check_service_enabled(service)

        status_text = f"{active_status} {enabled_status}".lower()
        not_found_markers = [
            "could not be found",
            "not-found",
            "not found",
            "no such file",
            "unknown",
            "unsupported",
            "command failed",
        ]
        installed = not any(marker in status_text for marker in not_found_markers)

        return {
            "service": service,
            "installed": installed,
            "active": active,
            "enabled": enabled,
            "active_status": active_status,
            "enabled_status": enabled_status,
        }

    def _platform_remediation_command(
        self,
        template_key: str,
        default: str,
        **kwargs: Any,
    ) -> str:
        """Render a remediation command from platform profile.

        Args:
            template_key: Profile template key
            default: Fallback command if template missing
            **kwargs: Template variables

        Returns:
            Rendered command string
        """
        rendered = self.platform_context.render_remediation(template_key, **kwargs)
        return rendered if rendered else default

    def _platform_install_packages_command(self, packages: str) -> str:
        """Render install packages command for current platform.

        Args:
            packages: Space-separated package names

        Returns:
            Platform-specific install command
        """
        return self._platform_remediation_command(
            "install_packages",
            f"sudo dnf install {packages}",
            packages=packages,
        )

    def _platform_remove_packages_command(self, packages: str) -> str:
        """Render remove packages command for current platform.

        Args:
            packages: Space-separated package names

        Returns:
            Platform-specific remove command
        """
        return self._platform_remediation_command(
            "remove_packages",
            f"sudo dnf remove {packages}",
            packages=packages,
        )

    def _platform_status_service_command(self, service: str, sudo: bool = False) -> str:
        """Render service status command for current platform.

        Args:
            service: Service name
            sudo: Whether to force sudo prefix in fallback mode

        Returns:
            Platform-specific service status command
        """
        fallback_prefix = "sudo " if sudo else ""
        return self._platform_remediation_command(
            "status_service",
            f"{fallback_prefix}systemctl status {service}",
            service=service,
        )

    def _platform_disable_service_command(self, service: str) -> str:
        """Render service disable command for current platform."""
        return self._platform_remediation_command(
            "disable_service",
            f"sudo systemctl disable {service}",
            service=service,
        )

    def _platform_stop_service_command(self, service: str) -> str:
        """Render service stop command for current platform."""
        return self._platform_remediation_command(
            "stop_service",
            f"sudo systemctl stop {service}",
            service=service,
        )

    def _platform_reload_service_command(self, service: str) -> str:
        """Render service reload command for current platform.

        Args:
            service: Service name

        Returns:
            Platform-specific service reload command
        """
        return self._platform_remediation_command(
            "reload_service",
            f"sudo systemctl reload {service}",
            service=service,
        )

    def _platform_grub_mkconfig_command(self, output: str) -> str:
        """Render GRUB regeneration command for current platform."""
        return self._platform_remediation_command(
            "grub_mkconfig",
            f"sudo grub2-mkconfig -o {output}",
            output=output,
        )

    def _platform_grub_password_hash_command(self) -> str:
        """Render GRUB password hash generation command for current platform."""
        return self._platform_remediation_command(
            "grub_password_hash",
            "sudo grub2-mkpasswd-pbkdf2",
        )
    
    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check.
        
        This method must be implemented by all check subclasses.
        It performs the actual audit check and returns a CheckResult.
        
        Returns:
            CheckResult containing the outcome of the check
        """
        pass
    
    def should_skip(self) -> bool:
        """Determine if this check should be skipped.
        
        Checks should be skipped if they require root privileges
        but the current execution context doesn't have them.
        
        Returns:
            True if the check should be skipped, False otherwise
        """
        return self.requires_root and not self._privileged
    
    def execute(self) -> CheckResult:
        """Execute the check with privilege checking.
        
        This is the main entry point for running a check. It handles
        privilege verification and delegates to run() if appropriate.
        
        Returns:
            CheckResult - either from the check execution or a skip result
        """
        if self.should_skip():
            return CheckResult.skipped_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Check '{self.name}' skipped - requires root privileges",
                severity=self.severity,
                requires_root=self.requires_root,
            )
        
        try:
            return self.run()
        except Exception as e:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Check execution failed with error: {str(e)}",
                remediation="Check system logs and verify check implementation",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"error": str(e), "error_type": type(e).__name__},
            )
    
    def get_metadata(self) -> dict[str, Any]:
        """Get check metadata as a dictionary.
        
        Returns:
            Dictionary containing check metadata
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "requires_root": self.requires_root,
            "expensive": self.expensive,
            "optional": self.optional,
        }
