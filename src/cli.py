"""
CatoScan - Command Line Interface

This module provides the CLI argument parsing, privilege handling,
and main entry point for the CIS audit tool.
"""

import argparse
import os
import sys
import traceback
from pathlib import Path
from typing import Optional

from src.core.check import CheckResult
from src.core.detector import EnvironmentDetector, DetectionResult, EnvironmentType
from src.core.platform import (
    PlatformContext,
    get_platform_context,
    list_available_profiles,
    profile_exists,
)
from src.core.registry import CheckRegistry
from src.output.json_formatter import JSONFormatter
from src.output.progress import create_progress_bar, ProgressBar, NullProgressBar


class PrivilegeChecker:
    """Handles privilege checking and warnings for the audit tool.
    
    Some CIS checks require root access to read system files, inspect
    service configurations, or verify system-level settings.
    """
    
    # Checks that require root privileges
    PRIVILEGED_CHECKS: list[str] = [
        "filesystem_permissions",
        "audit_configuration",
        "shadow_permissions",
        "service_status",
        "kernel_parameters",
    ]
    
    def __init__(self, skip_check: bool = False) -> None:
        """Initialize the privilege checker.
        
        Args:
            skip_check: If True, skip the sudo check entirely
        """
        self._skip_check = skip_check
        self._has_root = False
        self._warnings: list[str] = []
    
    def check_privileges(self) -> bool:
        """Check if the script is running with root/sudo privileges.
        
        Returns:
            True if running as root or with sudo, False otherwise
        """
        if self._skip_check:
            self._warnings.append(
                "Privilege check skipped (--no-sudo). Some checks may fail."
            )
            return False
        
        # Check for root user (uid 0)
        self._has_root = os.geteuid() == 0
        
        if not self._has_root:
            self._warnings.append(
                "Not running with sudo/root privileges. "
                "Some checks will be skipped."
            )
            self._warnings.append(
                f"Checks requiring root: {', '.join(self.PRIVILEGED_CHECKS)}"
            )
        
        return self._has_root
    
    def print_warnings(self) -> None:
        """Print any privilege-related warnings to stderr."""
        for warning in self._warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    
    @property
    def has_warnings(self) -> bool:
        """Check if any warnings were generated."""
        return len(self._warnings) > 0
    
    @property
    def privileged_checks(self) -> list[str]:
        """Get the list of checks requiring root privileges."""
        return self.PRIVILEGED_CHECKS.copy()


class CLI:
    """Command Line Interface for the CIS Audit Tool.
    
    Handles argument parsing, environment detection, privilege checking,
    and orchestrates the audit execution.
    """
    
    def __init__(self) -> None:
        """Initialize the CLI."""
        self.args: Optional[argparse.Namespace] = None
        self.detection_result: Optional[DetectionResult] = None
        self.platform_context: Optional[PlatformContext] = None
        self.privilege_checker = PrivilegeChecker()
        self._progress_bar: Optional[ProgressBar] = None
    
    def parse_args(self, argv: Optional[list[str]] = None) -> argparse.Namespace:
        """Parse command line arguments.
        
        Args:
            argv: Command line arguments (defaults to sys.argv[1:])
            
        Returns:
            Parsed arguments namespace
        """
        parser = argparse.ArgumentParser(
            prog="catoscan",
            description="CIS Benchmark Audit Tool",
            epilog="Exit codes: 0=all checks passed, 1=error, 2=warnings/check failures"
        )
        
        parser.add_argument(
            "--output", "-o",
            type=str,
            default=None,
            help="Output file path (default: stdout)"
        )
        
        parser.add_argument(
            "--verbose", "-v",
            action="store_true",
            help="Enable verbose output"
        )
        
        parser.add_argument(
            "--force-desktop",
            action="store_true",
            help="Force desktop environment detection"
        )
        
        parser.add_argument(
            "--force-server",
            action="store_true",
            help="Force server environment detection"
        )
        
        parser.add_argument(
            "--no-sudo",
            action="store_true",
            help="Skip sudo check, run without privileges"
        )
        
        parser.add_argument(
            "--no-progress",
            action="store_true",
            help="Disable progress bar display"
        )
        
        parser.add_argument(
            "--pretty",
            action="store_true",
            help="Pretty-print JSON output with indentation"
        )

        parser.add_argument(
            "--profile",
            type=str,
            default=None,
            help=(
                "Platform profile override (e.g., fedora-43, ubuntu-24.04). "
                "Defaults to auto-detection from /etc/os-release"
            ),
        )
        
        parser.add_argument(
            "--full",
            action="store_true",
            help="Include expensive/optional checks (may take longer)"
        )
        
        parser.add_argument(
            "--include-expensive",
            action="store_true",
            help="Alias for --full: include expensive/optional checks"
        )
        
        self.args = parser.parse_args(argv)
        return self.args

    def _ensure_platform_context(self) -> PlatformContext:
        """Load and cache the active platform context.

        Returns:
            PlatformContext selected by CLI profile override or auto-detection
        """
        if self.platform_context is None:
            profile_id = None
            if self.args is not None and self.args.profile:
                profile_id = self.args.profile
                if not profile_exists(profile_id):
                    available = ", ".join(list_available_profiles())
                    raise ValueError(
                        f"Unknown platform profile '{profile_id}'. "
                        f"Available profiles: {available}"
                    )
            self.platform_context = get_platform_context(profile_id=profile_id)
        return self.platform_context
    
    def detect_environment(self) -> DetectionResult:
        """Detect the system environment type.
        
        Uses the EnvironmentDetector with optional CLI overrides.
        
        Returns:
            DetectionResult with environment information
            
        Raises:
            ValueError: If both force_desktop and force_server are specified
        """
        if self.args is None:
            raise RuntimeError("Arguments must be parsed before environment detection")
        
        if self.args.force_desktop and self.args.force_server:
            raise ValueError(
                "Cannot specify both --force-desktop and --force-server"
            )
        
        detector = EnvironmentDetector(
            force_desktop=self.args.force_desktop,
            force_server=self.args.force_server,
            platform_context=self._ensure_platform_context(),
        )
        
        self.detection_result = detector.detect()
        return self.detection_result
    
    def print_environment_info(self) -> None:
        """Print detected environment information (verbose mode only)."""
        if not self.args or not self.args.verbose:
            return
        
        if self.detection_result is None:
            return
        
        print(f"Detected environment: {self.detection_result.environment.value}")
        print(f"Confidence: {self.detection_result.confidence:.2f}")
        
        if self.detection_result.override_used:
            print("Note: Environment override was applied via CLI flag")
        
        if self.detection_result.signals:
            print("Signals detected:")
            for signal, weight in sorted(
                self.detection_result.signals.items(),
                key=lambda x: x[1],
                reverse=True
            ):
                print(f"  - {signal}: {weight:.2f}")
    
    def run_audit(self, privileged: Optional[bool] = None) -> int:
        """Run the CIS audit.
        
        Loads all checks from the registry, executes them with appropriate
        privilege handling, and outputs results in JSON format.
        
        Returns:
            Exit code (0=success, 1=error, 2=warnings)
        """
        if self.args and self.args.verbose:
            print("Running CIS audit...", file=sys.stderr)
        
        # Initialize registry and discover checks
        registry = CheckRegistry()
        discovered = registry.discover()
        
        if self.args and self.args.verbose:
            print(f"Discovered {discovered} checks", file=sys.stderr)
        
        # Run all checks with appropriate privilege level
        if privileged is None:
            privileged = self.privilege_checker.check_privileges()

        # Load platform profile context (distro abstraction)
        platform_context = self._ensure_platform_context()
        
        # Determine if we should include expensive checks
        include_expensive = (self.args.full or self.args.include_expensive) if self.args else False
        
        # Determine if we should show progress bar
        disable_progress = self.args.no_progress if self.args else False

        # Determine total checks to execute (after filtering)
        total_checks = len(registry.get_checks(include_expensive=include_expensive))

        if self.args and self.args.verbose:
            print(f"Executing {total_checks} checks", file=sys.stderr)

        if registry.has_discovery_errors:
            print(
                f"WARNING: {len(registry.discovery_errors)} check module(s) failed to import during discovery",
                file=sys.stderr,
            )
            if self.args and self.args.verbose:
                for err in registry.discovery_errors[:10]:
                    print(f"  - {err}", file=sys.stderr)
                if len(registry.discovery_errors) > 10:
                    remaining = len(registry.discovery_errors) - 10
                    print(f"  ... and {remaining} more", file=sys.stderr)

        if discovered == 0:
            print(
                "Error: No checks were discovered. Verify your installation and check modules.",
                file=sys.stderr,
            )
            return 1
        
        # Create progress bar
        self._progress_bar = create_progress_bar(
            total=total_checks,
            verbose=self.args.verbose if self.args else False,
            disable=disable_progress
        )
        
        # Define progress callback for registry
        current_index = [0]  # Use list for mutable closure
        
        def progress_callback(event_type: str, check_id: str, check_name: str, result: Optional[CheckResult]) -> None:
            if self._progress_bar is None or isinstance(self._progress_bar, NullProgressBar):
                return
            if event_type == 'start':
                current_index[0] += 1
                self._progress_bar.update(
                    current=current_index[0],
                    check_id=check_id,
                    check_name=check_name,
                    status="running"
                )
            elif event_type == 'complete' and result:
                self._progress_bar.on_check_complete(
                    check_id, check_name, result.passed, result.skipped
                )
        
        if self.args and self.args.verbose:
            if include_expensive:
                print("Including expensive/optional checks (--full mode)", file=sys.stderr)
            else:
                print("Skipping expensive checks (use --full to include them)", file=sys.stderr)
        
        # Run checks with progress callback
        with self._progress_bar:
            results = registry.run_all(
                privileged=privileged,
                progress_callback=progress_callback if not disable_progress else None,
                include_expensive=include_expensive,
                platform_context=platform_context,
            )
        
        # Format results as JSON
        formatter = JSONFormatter(pretty=self.args.pretty if self.args else False)

        # Output to file or stdout
        try:
            if self.args and self.args.output:
                output_path = Path(self.args.output)
                formatter.write_to_file(
                    results,
                    output_path,
                    detection_result=self.detection_result,
                    privileged=privileged,
                    platform_context=platform_context,
                )
                if self.args.verbose:
                    print(f"Results written to {output_path}", file=sys.stderr)
            else:
                formatter.write_to_stdout(
                    results,
                    detection_result=self.detection_result,
                    privileged=privileged,
                    platform_context=platform_context,
                )
        except BrokenPipeError:
            # Common when piping to tools like `head`; treat as graceful termination.
            return 0
        except (OSError, UnicodeError) as e:
            print(f"Error writing audit output: {e}", file=sys.stderr)
            return 1
        
        # Determine exit code based on results
        failed_count = sum(1 for r in results if not r.passed and not r.skipped)
        
        if failed_count > 0:
            return 2  # Warnings - some checks failed
        
        return 0
    
    def main(self, argv: Optional[list[str]] = None) -> int:
        """Main entry point for the CLI.
        
        Args:
            argv: Command line arguments (defaults to sys.argv[1:])
            
        Returns:
            Exit code (0=success, 1=error, 2=warnings)
        """
        try:
            # Parse arguments
            self.parse_args(argv)

            # Validate platform profile selection early for clearer errors.
            self._ensure_platform_context()
            
            # Check privileges
            self.privilege_checker = PrivilegeChecker(
                skip_check=self.args.no_sudo if self.args else False
            )
            privileged = self.privilege_checker.check_privileges()
            
            # Print privilege warnings
            self.privilege_checker.print_warnings()
            
            # Detect environment
            self.detect_environment()
            self.print_environment_info()
            
            # Run the audit
            audit_exit_code = self.run_audit(privileged=privileged)
            
            # Determine final exit code
            if audit_exit_code != 0:
                return audit_exit_code
            
            if self.privilege_checker.has_warnings:
                return 2  # Warnings present
            
            return 0  # Success
            
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\nAudit interrupted by user", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            if self.args and self.args.verbose:
                traceback.print_exc()
            return 1


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for the CIS Audit Tool CLI.
    
    Args:
        argv: Command line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code (0=success, 1=error, 2=warnings)
    """
    cli = CLI()
    return cli.main(argv)


if __name__ == "__main__":
    sys.exit(main())
