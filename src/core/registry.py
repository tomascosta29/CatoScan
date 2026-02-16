"""
CatoScan - Check Registry

This module provides auto-discovery and registration of CIS checks.
"""

import importlib.util
import inspect
import os
import pkgutil
import sys
from pathlib import Path
import hashlib
from typing import Type, Optional, Callable, TYPE_CHECKING

from .check import BaseCheck, CheckResult, Severity

if TYPE_CHECKING:
    from .platform import PlatformContext


class CheckRegistry:
    """Registry for CIS check classes with auto-discovery support.
    
    The registry manages the collection of check classes and provides
    methods for registration, discovery, and execution of checks.
    
    Example:
        registry = CheckRegistry()
        
        # Auto-discover all checks in src/checks/
        registry.discover()
        
        # Get all checks that don't require root
        unprivileged_checks = registry.get_checks(requires_root=False)
        
        # Run all checks with root privileges
        results = registry.run_all(privileged=True)
    """
    
    def __init__(self) -> None:
        """Initialize an empty check registry."""
        self._checks: dict[str, Type[BaseCheck]] = {}
        self._results: list[CheckResult] = []
        self._discovery_errors: list[str] = []
    
    def register(self, check_class: Type[BaseCheck]) -> None:
        """Register a check class with the registry.
        
        Args:
            check_class: A class that inherits from BaseCheck
            
        Raises:
            TypeError: If check_class is not a subclass of BaseCheck
            ValueError: If a check with the same id is already registered
        """
        if not inspect.isclass(check_class):
            raise TypeError(f"Expected a class, got {type(check_class).__name__}")
        
        if not issubclass(check_class, BaseCheck):
            raise TypeError(
                f"Check class must inherit from BaseCheck, "
                f"got {check_class.__name__}"
            )
        
        check_id = check_class.id
        
        if check_id in self._checks:
            raise ValueError(
                f"Check with id '{check_id}' is already registered "
                f"({self._checks[check_id].__name__})"
            )
        
        self._checks[check_id] = check_class
    
    def unregister(self, check_id: str) -> None:
        """Remove a check from the registry.
        
        Args:
            check_id: The unique identifier of the check to remove
            
        Raises:
            KeyError: If the check_id is not registered
        """
        if check_id not in self._checks:
            raise KeyError(f"Check with id '{check_id}' is not registered")
        
        del self._checks[check_id]
    
    def discover(self, package_path: Optional[str] = None) -> int:
        """Auto-discover and register all check modules.
        
        Scans the specified package (or src/checks/ by default) for
        modules containing BaseCheck subclasses and registers them.
        
        Args:
            package_path: Path to the checks package (default: src/checks/)
            
        Returns:
            Number of check classes discovered and registered
        """
        if package_path is None:
            # Default to src/checks/ relative to project root
            project_root = Path(__file__).parent.parent.parent
            package_path = str(project_root / "src" / "checks")

        # Reset discovery errors for each run
        self._discovery_errors.clear()
        
        discovered_count = 0
        
        # Ensure the path exists
        if not os.path.exists(package_path):
            return 0
        
        # Add parent directory to path for import
        parent_dir = str(Path(package_path).parent)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        
        # Iterate through all modules in the checks package directory
        package_dir = Path(package_path)
        
        for _, module_name, is_pkg in pkgutil.iter_modules([package_path]):
            # Skip __init__ and non-python files
            if module_name.startswith("_") or is_pkg:
                continue

            module_file = package_dir / f"{module_name}.py"
            if not module_file.exists():
                continue

            # Use deterministic unique module names per file path to avoid
            # package name collisions with already-imported modules.
            module_digest = hashlib.sha1(str(module_file).encode("utf-8")).hexdigest()[:12]
            full_module_name = f"_catoscan_discovery_{module_name}_{module_digest}"

            try:
                spec = importlib.util.spec_from_file_location(full_module_name, module_file)
                if spec is None or spec.loader is None:
                    self._discovery_errors.append(
                        f"{module_file}: import spec creation failed"
                    )
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[full_module_name] = module
                spec.loader.exec_module(module)
                
                # Find all BaseCheck subclasses in the module
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BaseCheck) 
                        and obj is not BaseCheck
                        and not inspect.isabstract(obj)
                    ):
                        try:
                            self.register(obj)
                            discovered_count += 1
                        except ValueError:
                            # Already registered, skip
                            pass
                        
            except ImportError as e:
                # Record import errors but continue discovery.
                self._discovery_errors.append(
                    f"{module_file}: ImportError: {e}"
                )
                continue
            except Exception as e:
                # Record all module load errors but keep discovering others.
                self._discovery_errors.append(
                    f"{module_file}: {type(e).__name__}: {e}"
                )
                continue
        
        return discovered_count
    
    def get_check(self, check_id: str) -> Optional[Type[BaseCheck]]:
        """Get a registered check class by id.
        
        Args:
            check_id: The unique identifier of the check
            
        Returns:
            The check class if found, None otherwise
        """
        return self._checks.get(check_id)
    
    def get_checks(
        self, 
        requires_root: Optional[bool] = None,
        include_expensive: bool = False
    ) -> list[Type[BaseCheck]]:
        """Get all registered check classes, optionally filtered.
        
        Args:
            requires_root: If specified, filter by privilege requirement
            include_expensive: If False, exclude expensive/optional checks
            
        Returns:
            List of check classes matching the filter criteria
        """
        checks = list(self._checks.values())
        
        if requires_root is not None:
            checks = [
                check for check in checks 
                if check.requires_root == requires_root
            ]
        
        # Filter out expensive/optional checks unless explicitly included
        if not include_expensive:
            checks = [
                check for check in checks
                if not check.expensive and not check.optional
            ]
        
        # Sort by id for consistent ordering
        return sorted(checks, key=lambda c: c.id)
    
    def get_check_ids(self) -> list[str]:
        """Get a list of all registered check ids.
        
        Returns:
            List of check identifiers
        """
        return sorted(self._checks.keys())
    
    def run_all(
        self, 
        privileged: bool = False,
        check_ids: Optional[list[str]] = None,
        progress_callback: Optional[Callable[[str, str, str, Optional[CheckResult]], None]] = None,
        include_expensive: bool = False,
        platform_context: Optional["PlatformContext"] = None,
    ) -> list[CheckResult]:
        """Execute all applicable checks.
        
        Args:
            privileged: Whether checks should run with root privileges
            check_ids: Optional list of specific check ids to run
            progress_callback: Optional callback function called before and after
                each check. Called with (event_type, check_id, check_name, result) where
                event_type is 'start' or 'complete', and result is the CheckResult
                (only provided for 'complete' events).
            include_expensive: If True, include expensive/optional checks
            platform_context: Optional platform context for distro-specific behavior
                
        Returns:
            List of CheckResult objects from all executed checks
        """
        results: list[CheckResult] = []
        
        # Get checks to run
        if check_ids:
            check_classes = []
            for cid in check_ids:
                check_class = self.get_check(cid)
                if check_class:
                    # Skip expensive checks unless explicitly requested
                    if not include_expensive and (check_class.expensive or check_class.optional):
                        # Create a skipped result for expensive checks
                        results.append(CheckResult(
                            check_id=cid,
                            check_name=check_class.name,
                            passed=False,
                            skipped=True,
                            message=f"Check '{check_class.name}' skipped - requires --full flag (expensive check)",
                            remediation="Run with --full or --include-expensive to include this check",
                            severity=check_class.severity,
                            requires_root=check_class.requires_root,
                        ))
                        continue
                    check_classes.append(check_class)
                else:
                    # Create a failed result for unknown check ids
                    results.append(CheckResult(
                        check_id=cid,
                        check_name="Unknown Check",
                        passed=False,
                        skipped=False,
                        message=f"Check '{cid}' is not registered",
                        remediation="Verify the check id is correct and the check module is loaded",
                        severity=Severity.MEDIUM,
                        requires_root=False,
                    ))
        else:
            check_classes = self.get_checks(include_expensive=include_expensive)
        
        # Execute each check
        for i, check_class in enumerate(check_classes, 1):
            check_id = check_class.id
            check_name = check_class.name
            
            # Call progress callback before check starts
            if progress_callback:
                progress_callback('start', check_id, check_name, None)
            
            check_instance = check_class(
                privileged=privileged,
                platform_context=platform_context,
            )
            result = check_instance.execute()
            results.append(result)
            
            # Call progress callback after check completes
            if progress_callback:
                progress_callback('complete', check_id, check_name, result)
        
        self._results = results
        return results
    
    def run_check(
        self,
        check_id: str,
        privileged: bool = False,
        platform_context: Optional["PlatformContext"] = None,
    ) -> CheckResult:
        """Execute a single check by id.
        
        Args:
            check_id: The unique identifier of the check to run
            privileged: Whether the check should run with root privileges
            platform_context: Optional platform context for distro-specific behavior
            
        Returns:
            CheckResult from the check execution
            
        Raises:
            KeyError: If the check_id is not registered
        """
        check_class = self.get_check(check_id)
        if check_class is None:
            raise KeyError(f"Check with id '{check_id}' is not registered")
        
        check_instance = check_class(
            privileged=privileged,
            platform_context=platform_context,
        )
        return check_instance.execute()
    
    def clear(self) -> None:
        """Clear all registered checks and results."""
        self._checks.clear()
        self._results.clear()
        self._discovery_errors.clear()

    @property
    def discovery_errors(self) -> list[str]:
        """Get module discovery/import errors from the last discover run."""
        return self._discovery_errors.copy()

    @property
    def has_discovery_errors(self) -> bool:
        """Check whether discover encountered import/module load errors."""
        return bool(self._discovery_errors)
    
    def __len__(self) -> int:
        """Return the number of registered checks."""
        return len(self._checks)
    
    def __contains__(self, check_id: str) -> bool:
        """Check if a check id is registered."""
        return check_id in self._checks
