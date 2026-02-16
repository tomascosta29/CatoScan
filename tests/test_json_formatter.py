"""
CIS Audit Tool for Fedora 43 - JSON Formatter Tests

Tests for the JSON output formatter functionality.
"""

import json
import pytest
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.check import CheckResult, Severity
from src.core.detector import DetectionResult, EnvironmentType
from src.core.platform import DistroInfo, PlatformContext
from src.output.json_formatter import JSONFormatter, DateTimeEncoder


class TestDateTimeEncoder:
    """Tests for the DateTimeEncoder class."""
    
    def test_datetime_serialization(self) -> None:
        """Test that datetime objects are serialized to ISO format."""
        encoder = DateTimeEncoder()
        dt = datetime(2026, 2, 16, 12, 30, 45)
        result = encoder.default(dt)
        assert result == "2026-02-16T12:30:45"
    
    def test_severity_serialization(self) -> None:
        """Test that Severity enums are serialized to uppercase strings."""
        encoder = DateTimeEncoder()
        result = encoder.default(Severity.HIGH)
        assert result == "HIGH"
    
    def test_default_fallback(self) -> None:
        """Test that unknown types fall back to default behavior."""
        encoder = DateTimeEncoder()
        with pytest.raises(TypeError):
            encoder.default(object())


class TestJSONFormatterInit:
    """Tests for JSONFormatter initialization."""
    
    def test_default_initialization(self) -> None:
        """Test default initialization (non-pretty)."""
        formatter = JSONFormatter()
        assert formatter._pretty is False
    
    def test_pretty_initialization(self) -> None:
        """Test initialization with pretty=True."""
        formatter = JSONFormatter(pretty=True)
        assert formatter._pretty is True


class TestJSONFormatterFormat:
    """Tests for JSONFormatter.format() method."""
    
    def test_empty_results(self) -> None:
        """Test formatting with empty results list."""
        formatter = JSONFormatter()
        result = formatter.format([])
        
        parsed = json.loads(result)
        assert "metadata" in parsed
        assert "summary" in parsed
        assert "checks" in parsed
        assert parsed["summary"]["total_checks"] == 0
        assert parsed["summary"]["passed"] == 0
        assert parsed["summary"]["failed"] == 0
        assert parsed["summary"]["skipped"] == 0
    
    def test_single_passed_result(self) -> None:
        """Test formatting a single passed result."""
        formatter = JSONFormatter()
        results = [
            CheckResult.passed_result(
                check_id="test_check",
                check_name="Test Check",
                message="All good",
                severity=Severity.HIGH
            )
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        assert parsed["summary"]["total_checks"] == 1
        assert parsed["summary"]["passed"] == 1
        assert parsed["summary"]["failed"] == 0
        assert parsed["summary"]["skipped"] == 0
        
        check = parsed["checks"][0]
        assert check["id"] == "test_check"
        assert check["name"] == "Test Check"
        assert check["passed"] is True
        assert check["skipped"] is False
        assert check["severity"] == "HIGH"
        assert check["message"] == "All good"
    
    def test_single_failed_result(self) -> None:
        """Test formatting a single failed result."""
        formatter = JSONFormatter()
        results = [
            CheckResult.failed_result(
                check_id="fail_check",
                check_name="Fail Check",
                message="Something failed",
                remediation="Fix it",
                severity=Severity.CRITICAL
            )
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        assert parsed["summary"]["total_checks"] == 1
        assert parsed["summary"]["passed"] == 0
        assert parsed["summary"]["failed"] == 1
        assert parsed["summary"]["skipped"] == 0
        
        check = parsed["checks"][0]
        assert check["id"] == "fail_check"
        assert check["passed"] is False
        assert check["skipped"] is False
        assert check["severity"] == "CRITICAL"
        assert check["message"] == "Something failed"
        assert check["remediation"] == "Fix it"
    
    def test_skipped_result(self) -> None:
        """Test formatting a skipped result."""
        formatter = JSONFormatter()
        results = [
            CheckResult.skipped_result(
                check_id="skip_check",
                check_name="Skip Check",
                message="No privileges",
                severity=Severity.MEDIUM
            )
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        assert parsed["summary"]["total_checks"] == 1
        assert parsed["summary"]["passed"] == 0
        assert parsed["summary"]["failed"] == 0
        assert parsed["summary"]["skipped"] == 1
        
        check = parsed["checks"][0]
        assert check["passed"] is False
        assert check["skipped"] is True
    
    def test_mixed_results(self) -> None:
        """Test formatting mixed results (passed, failed, skipped)."""
        formatter = JSONFormatter()
        results = [
            CheckResult.passed_result(
                check_id="check1",
                check_name="Check 1",
                severity=Severity.HIGH
            ),
            CheckResult.failed_result(
                check_id="check2",
                check_name="Check 2",
                severity=Severity.MEDIUM
            ),
            CheckResult.skipped_result(
                check_id="check3",
                check_name="Check 3",
                severity=Severity.LOW
            ),
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        assert parsed["summary"]["total_checks"] == 3
        assert parsed["summary"]["passed"] == 1
        assert parsed["summary"]["failed"] == 1
        assert parsed["summary"]["skipped"] == 1
    
    def test_severity_breakdown(self) -> None:
        """Test that severity breakdown is correctly calculated."""
        formatter = JSONFormatter()
        results = [
            CheckResult.passed_result(
                check_id="critical_pass",
                check_name="Critical Pass",
                severity=Severity.CRITICAL
            ),
            CheckResult.failed_result(
                check_id="critical_fail",
                check_name="Critical Fail",
                severity=Severity.CRITICAL
            ),
            CheckResult.passed_result(
                check_id="high_pass",
                check_name="High Pass",
                severity=Severity.HIGH
            ),
            CheckResult.passed_result(
                check_id="medium_pass",
                check_name="Medium Pass",
                severity=Severity.MEDIUM
            ),
            CheckResult.skipped_result(
                check_id="low_skip",
                check_name="Low Skip",
                severity=Severity.LOW
            ),
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        by_severity = parsed["summary"]["by_severity"]
        
        # CRITICAL: 2 total, 1 passed, 1 failed
        assert by_severity["CRITICAL"]["total"] == 2
        assert by_severity["CRITICAL"]["passed"] == 1
        assert by_severity["CRITICAL"]["failed"] == 1
        
        # HIGH: 1 total, 1 passed, 0 failed
        assert by_severity["HIGH"]["total"] == 1
        assert by_severity["HIGH"]["passed"] == 1
        assert by_severity["HIGH"]["failed"] == 0
        
        # MEDIUM: 1 total, 1 passed, 0 failed
        assert by_severity["MEDIUM"]["total"] == 1
        assert by_severity["MEDIUM"]["passed"] == 1
        assert by_severity["MEDIUM"]["failed"] == 0
        
        # LOW: 1 total, 0 passed, 0 failed (skipped doesn't count as failed)
        assert by_severity["LOW"]["total"] == 1
        assert by_severity["LOW"]["passed"] == 0
        assert by_severity["LOW"]["failed"] == 0
    
    def test_metadata_content(self) -> None:
        """Test that metadata contains expected fields."""
        formatter = JSONFormatter()
        detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=0.85,
            signals={"sshd": 0.5},
            override_used=False
        )
        
        result = formatter.format(
            [],
            detection_result=detection_result,
            privileged=True
        )
        parsed = json.loads(result)
        
        metadata = parsed["metadata"]
        assert metadata["schema_version"] == JSONFormatter.SCHEMA_VERSION
        assert "timestamp" in metadata
        assert "hostname" in metadata
        assert metadata["fedora_version"] == "43"
        assert metadata["environment"] == "server"
        assert metadata["privileged"] is True
    
    def test_metadata_without_detection(self) -> None:
        """Test metadata when detection_result is None."""
        formatter = JSONFormatter()
        
        result = formatter.format([], detection_result=None, privileged=False)
        parsed = json.loads(result)
        
        metadata = parsed["metadata"]
        assert metadata["environment"] == "unknown"
        assert metadata["privileged"] is False

    def test_metadata_with_platform_context(self) -> None:
        """Test metadata includes platform fields when context is provided."""
        formatter = JSONFormatter()
        context = PlatformContext(
            profile_id="ubuntu-24.04",
            distro=DistroInfo(
                os_id="ubuntu",
                version_id="24.04",
                id_like=["debian"],
                pretty_name="Ubuntu 24.04 LTS",
            ),
            profile={
                "package_manager": {"name": "apt"},
                "service_manager": {"name": "systemd"},
            },
        )

        result = formatter.format([], platform_context=context)
        parsed = json.loads(result)

        metadata = parsed["metadata"]
        assert metadata["platform_profile"] == "ubuntu-24.04"
        assert metadata["distribution"] == "ubuntu"
        assert metadata["distribution_version"] == "24.04"
        assert metadata["distribution_name"] == "Ubuntu 24.04 LTS"
        assert metadata["package_manager"] == "apt"
        assert metadata["service_manager"] == "systemd"
    
    def test_pretty_output_format(self) -> None:
        """Test that pretty output includes newlines and indentation."""
        formatter = JSONFormatter(pretty=True)
        results = [
            CheckResult.passed_result(check_id="test", check_name="Test")
        ]
        
        result = formatter.format(results)
        
        # Pretty output should have newlines and indentation
        assert '\n' in result
        assert '  ' in result
    
    def test_compact_output_format(self) -> None:
        """Test that compact output has no newlines or spaces."""
        formatter = JSONFormatter(pretty=False)
        results = [
            CheckResult.passed_result(check_id="test", check_name="Test")
        ]
        
        result = formatter.format(results)
        
        # Compact output should not have newlines
        assert '\n' not in result
    
    def test_check_details_included(self) -> None:
        """Test that check details are included in output."""
        formatter = JSONFormatter()
        results = [
            CheckResult(
                check_id="detail_check",
                check_name="Detail Check",
                passed=True,
                details={"key1": "value1", "count": 42}
            )
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        check = parsed["checks"][0]
        assert check["details"] == {"key1": "value1", "count": 42}
    
    def test_empty_details_as_none(self) -> None:
        """Test that empty details are output as null."""
        formatter = JSONFormatter()
        results = [
            CheckResult.passed_result(
                check_id="no_detail",
                check_name="No Detail"
            )
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        check = parsed["checks"][0]
        assert check["details"] is None


class TestJSONFormatterWriteToFile:
    """Tests for JSONFormatter.write_to_file() method."""
    
    def test_write_to_file(self, tmp_path: Path) -> None:
        """Test writing JSON output to a file."""
        formatter = JSONFormatter()
        results = [
            CheckResult.passed_result(check_id="test", check_name="Test")
        ]
        
        output_file = tmp_path / "output.json"
        formatter.write_to_file(results, output_file)
        
        assert output_file.exists()
        content = output_file.read_text()
        parsed = json.loads(content)
        assert parsed["summary"]["total_checks"] == 1
    
    def test_write_to_file_with_detection(self, tmp_path: Path) -> None:
        """Test writing with detection result."""
        formatter = JSONFormatter()
        detection_result = DetectionResult(
            environment=EnvironmentType.DESKTOP,
            confidence=0.9,
            signals={}
        )
        
        output_file = tmp_path / "output.json"
        formatter.write_to_file([], output_file, detection_result, privileged=False)
        
        content = output_file.read_text()
        parsed = json.loads(content)
        assert parsed["metadata"]["environment"] == "desktop"


class TestJSONFormatterWriteToStdout:
    """Tests for JSONFormatter.write_to_stdout() method."""
    
    def test_write_to_stdout(self, capsys) -> None:
        """Test writing JSON output to stdout."""
        formatter = JSONFormatter()
        results = [
            CheckResult.passed_result(check_id="test", check_name="Test")
        ]
        
        formatter.write_to_stdout(results)
        
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["summary"]["total_checks"] == 1
    
    def test_pretty_stdout_adds_newline(self, capsys) -> None:
        """Test that pretty output adds trailing newline."""
        formatter = JSONFormatter(pretty=True)
        
        formatter.write_to_stdout([])
        
        captured = capsys.readouterr()
        assert captured.out.endswith('\n')


class TestJSONFormatterIntegration:
    """Integration tests for JSONFormatter."""
    
    def test_full_audit_simulation(self) -> None:
        """Simulate a full audit with multiple checks."""
        formatter = JSONFormatter(pretty=True)
        
        # Simulate various check results
        results = [
            CheckResult.passed_result(
                check_id="auth_password_complexity",
                check_name="Password Complexity",
                message="Password complexity requirements are configured",
                severity=Severity.HIGH
            ),
            CheckResult.failed_result(
                check_id="auth_account_lockout",
                check_name="Account Lockout Policy",
                message="Account lockout is not configured",
                remediation="Configure pam_faillock in /etc/pam.d/system-auth",
                severity=Severity.HIGH
            ),
            CheckResult.skipped_result(
                check_id="filesystem_permissions",
                check_name="Filesystem Permissions",
                message="Requires root privileges to check file permissions",
                severity=Severity.MEDIUM
            ),
            CheckResult.passed_result(
                check_id="logging_rsyslog",
                check_name="Rsyslog Service",
                message="rsyslog is installed and running",
                severity=Severity.MEDIUM
            ),
        ]
        
        detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=0.8,
            signals={"sshd": 0.5, "nginx": 0.75},
            override_used=False
        )
        
        result = formatter.format(results, detection_result, privileged=False)
        parsed = json.loads(result)
        
        # Verify structure
        assert "metadata" in parsed
        assert "summary" in parsed
        assert "checks" in parsed
        
        # Verify metadata
        assert parsed["metadata"]["fedora_version"] == "43"
        assert parsed["metadata"]["environment"] == "server"
        assert parsed["metadata"]["privileged"] is False
        
        # Verify summary
        assert parsed["summary"]["total_checks"] == 4
        assert parsed["summary"]["passed"] == 2
        assert parsed["summary"]["failed"] == 1
        assert parsed["summary"]["skipped"] == 1
        
        # Verify checks array
        assert len(parsed["checks"]) == 4
        
        # Verify each check has required fields
        for check in parsed["checks"]:
            assert "id" in check
            assert "name" in check
            assert "passed" in check
            assert "skipped" in check
            assert "severity" in check
            assert "message" in check
            assert "remediation" in check
    
    def test_output_schema_validation(self) -> None:
        """Validate output structure matches expected schema."""
        formatter = JSONFormatter()
        
        results = [
            CheckResult(
                check_id="test",
                check_name="Test",
                passed=True,
                message="Test message",
                remediation="",
                severity=Severity.LOW,
                details={"extra": "info"}
            )
        ]
        
        result = formatter.format(results)
        parsed = json.loads(result)
        
        # Validate metadata schema
        metadata = parsed["metadata"]
        assert isinstance(metadata["timestamp"], str)
        assert isinstance(metadata["hostname"], str)
        assert isinstance(metadata["schema_version"], str)
        assert isinstance(metadata["fedora_version"], str)
        assert isinstance(metadata["environment"], str)
        assert isinstance(metadata["privileged"], bool)
        assert isinstance(metadata["platform_profile"], str)
        assert isinstance(metadata["distribution"], str)
        assert isinstance(metadata["distribution_version"], str)
        assert isinstance(metadata["distribution_name"], str)
        assert isinstance(metadata["package_manager"], str)
        assert isinstance(metadata["service_manager"], str)
        
        # Validate summary schema
        summary = parsed["summary"]
        assert isinstance(summary["total_checks"], int)
        assert isinstance(summary["passed"], int)
        assert isinstance(summary["failed"], int)
        assert isinstance(summary["skipped"], int)
        assert isinstance(summary["by_severity"], dict)
        
        # Validate severity breakdown schema
        for severity, counts in summary["by_severity"].items():
            assert isinstance(counts["total"], int)
            assert isinstance(counts["passed"], int)
            assert isinstance(counts["failed"], int)
        
        # Validate checks schema
        for check in parsed["checks"]:
            assert isinstance(check["id"], str)
            assert isinstance(check["name"], str)
            assert isinstance(check["passed"], bool)
            assert isinstance(check["skipped"], bool)
            assert isinstance(check["severity"], str)
            assert isinstance(check["message"], str)
            assert isinstance(check["remediation"], str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
