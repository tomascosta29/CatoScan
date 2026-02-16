"""
CatoScan - JSON Output Formatter

This module provides JSON formatting capabilities for CIS audit results.
"""

import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..core.check import CheckResult, Severity
from ..core.detector import DetectionResult, EnvironmentType
from ..core.platform import PlatformContext


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime serialization."""
    
    def default(self, o: Any) -> Any:
        """Convert datetime objects to ISO format strings."""
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, Severity):
            return o.value.upper()
        return super().default(o)


class JSONFormatter:
    """Formatter for CIS audit results in JSON format.
    
    This class takes check results and produces structured JSON output
    with metadata, summary statistics, and detailed check results.
    
    Example:
        formatter = JSONFormatter()
        results = registry.run_all(privileged=True)
        detection_result = detector.detect()
        
        json_output = formatter.format(results, detection_result)
        print(json_output)
    """
    
    # Severity levels in order
    SEVERITY_LEVELS = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    SCHEMA_VERSION = "1.1"
    
    def __init__(self, pretty: bool = False) -> None:
        """Initialize the JSON formatter.
        
        Args:
            pretty: If True, output formatted JSON with indentation
        """
        self._pretty = pretty
    
    def format(
        self,
        results: list[CheckResult],
        detection_result: Optional[DetectionResult] = None,
        privileged: bool = False,
        platform_context: Optional[PlatformContext] = None,
    ) -> str:
        """Format check results as JSON.
        
        Args:
            results: List of CheckResult objects from audit execution
            detection_result: Optional environment detection result
            privileged: Whether the audit ran with root privileges
            platform_context: Optional platform context for distro metadata
            
        Returns:
            JSON string containing formatted audit results
        """
        output = self._build_output(
            results,
            detection_result,
            privileged,
            platform_context,
        )
        
        if self._pretty:
            return json.dumps(output, cls=DateTimeEncoder, indent=2, sort_keys=False)
        else:
            return json.dumps(output, cls=DateTimeEncoder, separators=(',', ':'))
    
    def _build_output(
        self,
        results: list[CheckResult],
        detection_result: Optional[DetectionResult],
        privileged: bool,
        platform_context: Optional[PlatformContext],
    ) -> dict[str, Any]:
        """Build the output dictionary structure.
        
        Args:
            results: List of CheckResult objects
            detection_result: Optional environment detection result
            privileged: Whether running with root privileges
            platform_context: Optional platform context for distro metadata
            
        Returns:
            Dictionary with metadata, summary, and checks
        """
        return {
            "metadata": self._build_metadata(
                detection_result,
                privileged,
                platform_context,
            ),
            "summary": self._build_summary(results),
            "checks": self._build_checks(results),
        }
    
    def _build_metadata(
        self,
        detection_result: Optional[DetectionResult],
        privileged: bool,
        platform_context: Optional[PlatformContext],
    ) -> dict[str, Any]:
        """Build the metadata section.
        
        Args:
            detection_result: Optional environment detection result
            privileged: Whether running with root privileges
            platform_context: Optional platform context for distro metadata
            
        Returns:
            Dictionary containing audit metadata
        """
        # Determine environment type
        if detection_result:
            environment = detection_result.environment.value
        else:
            environment = "unknown"
        
        profile_id = "unknown"
        distro_id = "unknown"
        distro_version = "unknown"
        distro_name = "unknown"
        package_manager = "unknown"
        service_manager = "unknown"

        if platform_context is not None:
            profile_id = platform_context.profile_id
            distro_id = platform_context.distro.os_id
            distro_version = platform_context.distro.version_id
            distro_name = platform_context.distro.pretty_name
            package_manager = platform_context.package_manager_name
            service_manager = platform_context.service_manager_name

        return {
            "schema_version": self.SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc),
            "hostname": socket.gethostname(),
            "fedora_version": "43",
            "environment": environment,
            "privileged": privileged,
            "platform_profile": profile_id,
            "distribution": distro_id,
            "distribution_version": distro_version,
            "distribution_name": distro_name,
            "package_manager": package_manager,
            "service_manager": service_manager,
        }
    
    def _build_summary(self, results: list[CheckResult]) -> dict[str, Any]:
        """Build the summary section with statistics.
        
        Args:
            results: List of CheckResult objects
            
        Returns:
            Dictionary containing summary statistics
        """
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed and not r.skipped)
        skipped = sum(1 for r in results if r.skipped)
        
        # Build severity breakdown
        by_severity: dict[str, dict[str, int]] = {}
        for severity in self.SEVERITY_LEVELS:
            severity_results = [r for r in results if r.severity == severity]
            severity_total = len(severity_results)
            severity_passed = sum(1 for r in severity_results if r.passed)
            severity_failed = sum(1 for r in severity_results if not r.passed and not r.skipped)
            
            by_severity[severity.value.upper()] = {
                "total": severity_total,
                "passed": severity_passed,
                "failed": severity_failed,
            }
        
        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "by_severity": by_severity,
        }
    
    def _build_checks(self, results: list[CheckResult]) -> list[dict[str, Any]]:
        """Build the checks array with detailed results.
        
        Args:
            results: List of CheckResult objects
            
        Returns:
            List of dictionaries containing check details
        """
        return [
            {
                "id": result.check_id,
                "name": result.check_name,
                "passed": result.passed,
                "skipped": result.skipped,
                "severity": result.severity.value.upper(),
                "message": result.message,
                "remediation": result.remediation,
                "details": result.details if result.details else None,
            }
            for result in results
        ]
    
    def write_to_file(
        self,
        results: list[CheckResult],
        output_path: Path,
        detection_result: Optional[DetectionResult] = None,
        privileged: bool = False,
        platform_context: Optional[PlatformContext] = None,
    ) -> None:
        """Write formatted JSON results to a file.
        
        Args:
            results: List of CheckResult objects
            output_path: Path to write the JSON file
            detection_result: Optional environment detection result
            privileged: Whether the audit ran with root privileges
            platform_context: Optional platform context for distro metadata
        """
        json_content = self.format(
            results,
            detection_result,
            privileged,
            platform_context,
        )
        output_path.write_text(json_content, encoding='utf-8')
    
    def write_to_stdout(
        self,
        results: list[CheckResult],
        detection_result: Optional[DetectionResult] = None,
        privileged: bool = False,
        platform_context: Optional[PlatformContext] = None,
    ) -> None:
        """Write formatted JSON results to stdout.
        
        Args:
            results: List of CheckResult objects
            detection_result: Optional environment detection result
            privileged: Whether the audit ran with root privileges
            platform_context: Optional platform context for distro metadata
        """
        json_content = self.format(
            results,
            detection_result,
            privileged,
            platform_context,
        )
        sys.stdout.write(json_content)
        if self._pretty:
            sys.stdout.write('\n')
