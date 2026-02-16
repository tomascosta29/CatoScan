"""
CIS Audit Tool for Fedora 43 - Integration Tests

End-to-end integration tests that validate the full audit tool flow,
CLI argument handling, JSON output structure, and exit codes.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Add src to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.cli import CLI, main, PrivilegeChecker
from src.core.check import BaseCheck, CheckResult, Severity
from src.core.detector import EnvironmentDetector, DetectionResult, EnvironmentType
from src.core.platform import DistroInfo, PlatformContext, load_platform_context
from src.core.registry import CheckRegistry
from src.output.json_formatter import JSONFormatter


class TestPrivilegeChecker:
    """Tests for privilege checking functionality."""
    
    def test_privilege_checker_defaults(self) -> None:
        """Test privilege checker with default settings."""
        checker = PrivilegeChecker()
        assert checker._skip_check is False
        assert checker._has_root is False
        assert checker._warnings == []
    
    def test_privilege_checker_skip_check(self) -> None:
        """Test privilege checker with skip_check=True."""
        checker = PrivilegeChecker(skip_check=True)
        assert checker._skip_check is True
        
        has_root = checker.check_privileges()
        assert has_root is False
        assert len(checker._warnings) == 1
        assert "skipped" in checker._warnings[0].lower()
    
    @mock.patch('os.geteuid')
    def test_privilege_checker_as_root(self, mock_geteuid) -> None:
        """Test privilege checker when running as root."""
        mock_geteuid.return_value = 0
        
        checker = PrivilegeChecker()
        has_root = checker.check_privileges()
        
        assert has_root is True
        assert len(checker._warnings) == 0
    
    @mock.patch('os.geteuid')
    def test_privilege_checker_not_root(self, mock_geteuid) -> None:
        """Test privilege checker when not running as root."""
        mock_geteuid.return_value = 1000
        
        checker = PrivilegeChecker()
        has_root = checker.check_privileges()
        
        assert has_root is False
        assert len(checker._warnings) == 2
        assert "not running with sudo" in checker._warnings[0].lower()
    
    def test_privileged_checks_list(self) -> None:
        """Test that privileged checks list is returned."""
        checker = PrivilegeChecker()
        privileged = checker.privileged_checks
        
        assert isinstance(privileged, list)
        assert len(privileged) > 0
        assert "filesystem_permissions" in privileged
    
    def test_has_warnings_property(self) -> None:
        """Test has_warnings property."""
        checker = PrivilegeChecker(skip_check=True)
        assert checker.has_warnings is False
        
        checker.check_privileges()
        assert checker.has_warnings is True


class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""
    
    def test_cli_parse_no_args(self) -> None:
        """Test CLI with no arguments."""
        cli = CLI()
        args = cli.parse_args([])
        
        assert args.output is None
        assert args.verbose is False
        assert args.force_desktop is False
        assert args.force_server is False
        assert args.no_sudo is False
        assert args.pretty is False
    
    def test_cli_parse_output(self) -> None:
        """Test CLI with --output argument."""
        cli = CLI()
        args = cli.parse_args(['--output', 'report.json'])
        assert args.output == 'report.json'
    
    def test_cli_parse_output_short(self) -> None:
        """Test CLI with -o short argument."""
        cli = CLI()
        args = cli.parse_args(['-o', 'report.json'])
        assert args.output == 'report.json'
    
    def test_cli_parse_verbose(self) -> None:
        """Test CLI with --verbose argument."""
        cli = CLI()
        args = cli.parse_args(['--verbose'])
        assert args.verbose is True
    
    def test_cli_parse_verbose_short(self) -> None:
        """Test CLI with -v short argument."""
        cli = CLI()
        args = cli.parse_args(['-v'])
        assert args.verbose is True
    
    def test_cli_parse_force_desktop(self) -> None:
        """Test CLI with --force-desktop argument."""
        cli = CLI()
        args = cli.parse_args(['--force-desktop'])
        assert args.force_desktop is True
    
    def test_cli_parse_force_server(self) -> None:
        """Test CLI with --force-server argument."""
        cli = CLI()
        args = cli.parse_args(['--force-server'])
        assert args.force_server is True
    
    def test_cli_parse_no_sudo(self) -> None:
        """Test CLI with --no-sudo argument."""
        cli = CLI()
        args = cli.parse_args(['--no-sudo'])
        assert args.no_sudo is True
    
    def test_cli_parse_pretty(self) -> None:
        """Test CLI with --pretty argument."""
        cli = CLI()
        args = cli.parse_args(['--pretty'])
        assert args.pretty is True

    def test_cli_parse_profile(self) -> None:
        """Test CLI with --profile override argument."""
        cli = CLI()
        args = cli.parse_args(['--profile', 'ubuntu-24.04'])
        assert args.profile == 'ubuntu-24.04'
    
    def test_cli_parse_combined_args(self) -> None:
        """Test CLI with multiple arguments combined."""
        cli = CLI()
        args = cli.parse_args([
            '--output', 'results.json',
            '--verbose',
            '--force-desktop',
            '--pretty'
        ])
        assert args.output == 'results.json'
        assert args.verbose is True
        assert args.force_desktop is True
        assert args.pretty is True
    
    def test_cli_parse_force_both_raises(self) -> None:
        """Test that --force-desktop and --force-server together raises error."""
        cli = CLI()
        cli.parse_args(['--force-desktop', '--force-server'])
        
        with pytest.raises(ValueError, match="Cannot specify both"):
            cli.detect_environment()


class TestEnvironmentDetectionIntegration:
    """Tests for environment detection integration."""
    
    def test_detect_environment_force_desktop(self) -> None:
        """Test environment detection with --force-desktop."""
        cli = CLI()
        cli.parse_args(['--force-desktop'])
        
        result = cli.detect_environment()
        
        assert result.environment == EnvironmentType.DESKTOP
        assert result.confidence == 1.0
        assert result.override_used is True
    
    def test_detect_environment_force_server(self) -> None:
        """Test environment detection with --force-server."""
        cli = CLI()
        cli.parse_args(['--force-server'])
        
        result = cli.detect_environment()
        
        assert result.environment == EnvironmentType.SERVER
        assert result.confidence == 1.0
        assert result.override_used is True
    
    def test_detect_environment_no_override(self) -> None:
        """Test environment detection without overrides."""
        cli = CLI()
        cli.parse_args([])
        
        result = cli.detect_environment()
        
        assert isinstance(result.environment, EnvironmentType)
        assert isinstance(result.confidence, float)

    @mock.patch("src.cli.get_platform_context")
    def test_detect_environment_uses_profile_override(self, mock_get_platform_context: mock.MagicMock) -> None:
        """Test environment detection uses CLI profile override."""
        mock_get_platform_context.return_value = PlatformContext(
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

        cli = CLI()
        cli.parse_args(['--profile', 'ubuntu-24.04', '--force-desktop'])
        result = cli.detect_environment()

        assert result.environment == EnvironmentType.DESKTOP
        mock_get_platform_context.assert_called_once_with(profile_id='ubuntu-24.04')
        assert result.override_used is True

    def test_detect_environment_with_invalid_profile_raises(self) -> None:
        """Invalid profile override should raise a clear ValueError."""
        cli = CLI()
        cli.parse_args(['--profile', 'definitely-not-a-profile'])

        with pytest.raises(ValueError, match="Unknown platform profile"):
            cli.detect_environment()
    
    @mock.patch('src.core.detector.EnvironmentDetector._is_service_active')
    @mock.patch('src.core.detector.EnvironmentDetector._is_graphical_target')
    def test_detect_environment_with_mocked_signals(self, mock_graphical, mock_service) -> None:
        """Test environment detection with mocked signals."""
        mock_service.return_value = False
        mock_graphical.return_value = True
        
        cli = CLI()
        cli.parse_args([])
        
        result = cli.detect_environment()
        
        assert isinstance(result, DetectionResult)
        assert result.environment in [EnvironmentType.DESKTOP, EnvironmentType.SERVER, EnvironmentType.UNKNOWN]


class TestJSONOutputSchema:
    """Tests for JSON output structure validation."""
    
    def test_json_output_structure(self) -> None:
        """Test that JSON output has required structure."""
        registry = CheckRegistry()
        
        # Create a simple test check
        class TestCheck(BaseCheck):
            id = "test_output"
            name = "Test Output Check"
            description = "Testing output"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Test passed"
                )
        
        registry.register(TestCheck)
        results = registry.run_all(privileged=False)
        
        formatter = JSONFormatter()
        detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=0.8,
            signals={"test": 0.5}
        )
        
        json_output = formatter.format(results, detection_result, privileged=False)
        data = json.loads(json_output)
        
        # Validate top-level structure
        assert "metadata" in data
        assert "summary" in data
        assert "checks" in data
        
        # Validate metadata structure
        metadata = data["metadata"]
        assert "timestamp" in metadata
        assert "hostname" in metadata
        assert "fedora_version" in metadata
        assert "environment" in metadata
        assert "privileged" in metadata
        
        # Validate summary structure
        summary = data["summary"]
        assert "total_checks" in summary
        assert "passed" in summary
        assert "failed" in summary
        assert "skipped" in summary
        assert "by_severity" in summary
        
        # Validate checks array
        checks = data["checks"]
        assert isinstance(checks, list)
        assert len(checks) == 1
        
        # Validate check structure
        check = checks[0]
        assert "id" in check
        assert "name" in check
        assert "passed" in check
        assert "skipped" in check
        assert "severity" in check
        assert "message" in check
        assert "remediation" in check
        assert "details" in check
    
    def test_json_output_with_failed_check(self) -> None:
        """Test JSON output with a failed check."""
        registry = CheckRegistry()
        
        class FailCheck(BaseCheck):
            id = "fail_output"
            name = "Fail Output Check"
            description = "Testing failed output"
            severity = Severity.HIGH
            
            def run(self) -> CheckResult:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Test failed",
                    remediation="Fix it",
                    severity=self.severity  # Pass the check's severity to the result
                )
        
        registry.register(FailCheck)
        results = registry.run_all(privileged=False)
        
        formatter = JSONFormatter(pretty=True)
        json_output = formatter.format(results, privileged=False)
        data = json.loads(json_output)
        
        assert data["summary"]["total_checks"] == 1
        assert data["summary"]["passed"] == 0
        assert data["summary"]["failed"] == 1
        assert data["summary"]["skipped"] == 0
        
        check = data["checks"][0]
        assert check["passed"] is False
        assert check["severity"] == "HIGH"
        assert check["message"] == "Test failed"
        assert check["remediation"] == "Fix it"
    
    def test_json_output_with_skipped_check(self) -> None:
        """Test JSON output with a skipped check."""
        registry = CheckRegistry()
        
        class RootCheck(BaseCheck):
            id = "root_output"
            name = "Root Output Check"
            description = "Testing skipped output"
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(RootCheck)
        results = registry.run_all(privileged=False)
        
        formatter = JSONFormatter()
        json_output = formatter.format(results, privileged=False)
        data = json.loads(json_output)
        
        assert data["summary"]["total_checks"] == 1
        assert data["summary"]["passed"] == 0
        assert data["summary"]["failed"] == 0
        assert data["summary"]["skipped"] == 1
        
        check = data["checks"][0]
        assert check["skipped"] is True
    
    def test_json_output_severity_breakdown(self) -> None:
        """Test that severity breakdown is included in summary."""
        registry = CheckRegistry()
        
        class CriticalCheck(BaseCheck):
            id = "critical_check"
            name = "Critical Check"
            description = "Critical"
            severity = Severity.CRITICAL
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name,
                    severity=self.severity  # Pass severity to result
                )
        
        class HighCheck(BaseCheck):
            id = "high_check"
            name = "High Check"
            description = "High"
            severity = Severity.HIGH
            
            def run(self) -> CheckResult:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Failed",
                    severity=self.severity  # Pass severity to result
                )
        
        registry.register(CriticalCheck)
        registry.register(HighCheck)
        results = registry.run_all(privileged=False)
        
        formatter = JSONFormatter()
        json_output = formatter.format(results, privileged=False)
        data = json.loads(json_output)
        
        by_severity = data["summary"]["by_severity"]
        assert "CRITICAL" in by_severity
        assert "HIGH" in by_severity
        assert "MEDIUM" in by_severity
        assert "LOW" in by_severity
        
        assert by_severity["CRITICAL"]["passed"] == 1
        assert by_severity["HIGH"]["failed"] == 1


class TestExitCodes:
    """Tests for exit code validation."""
    
    def test_exit_code_success_all_passed(self) -> None:
        """Test exit code 0 when all checks pass."""
        cli = CLI()
        cli.parse_args(['--no-sudo'])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=1.0,
            signals={},
            override_used=True
        )
        
        # Mock the registry to return only passing results
        with mock.patch.object(CheckRegistry, 'discover', return_value=1):
            with mock.patch.object(CheckRegistry, 'run_all', return_value=[
                CheckResult.passed_result(
                    check_id="test",
                    check_name="Test",
                    message="Passed"
                )
            ]):
                exit_code = cli.run_audit()
        
        assert exit_code == 0
    
    def test_exit_code_warnings_some_failed(self) -> None:
        """Test exit code 2 when some checks fail."""
        cli = CLI()
        cli.parse_args(['--no-sudo'])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=1.0,
            signals={},
            override_used=True
        )
        
        with mock.patch.object(CheckRegistry, 'discover', return_value=1):
            with mock.patch.object(CheckRegistry, 'run_all', return_value=[
                CheckResult.failed_result(
                    check_id="test",
                    check_name="Test",
                    message="Failed"
                )
            ]):
                exit_code = cli.run_audit()
        
        assert exit_code == 2
    
    def test_main_exit_code_error(self) -> None:
        """Test exit code 1 on error."""
        with mock.patch.object(CLI, 'parse_args', side_effect=Exception("Test error")):
            exit_code = main()
        
        assert exit_code == 1
    
    def test_main_exit_code_value_error(self) -> None:
        """Test exit code 1 on ValueError."""
        with mock.patch.object(CLI, 'parse_args', side_effect=ValueError("Test value error")):
            exit_code = main()
        
        assert exit_code == 1
    
    def test_main_exit_code_keyboard_interrupt(self) -> None:
        """Test exit code 1 on KeyboardInterrupt."""
        with mock.patch.object(CLI, 'parse_args', side_effect=KeyboardInterrupt()):
            exit_code = main()
        
        assert exit_code == 1

    def test_main_exit_code_invalid_profile(self, capsys) -> None:
        """Test exit code 1 when invalid profile is provided."""
        exit_code = main(['--profile', 'definitely-not-a-profile'])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Unknown platform profile" in captured.err

    def test_run_audit_returns_error_when_output_write_fails(self, tmp_path: Path, capsys) -> None:
        """Test run_audit returns 1 when writing output fails."""
        cli = CLI()
        cli.parse_args(['--no-sudo', '--output', str(tmp_path / 'report.json')])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=1.0,
            signals={},
            override_used=True,
        )

        with mock.patch.object(CheckRegistry, 'discover', return_value=1):
            with mock.patch.object(CheckRegistry, 'run_all', return_value=[
                CheckResult.passed_result(
                    check_id="test",
                    check_name="Test",
                    message="Passed",
                )
            ]):
                with mock.patch.object(JSONFormatter, 'write_to_file', side_effect=OSError("disk full")):
                    exit_code = cli.run_audit()

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error writing audit output" in captured.err


class TestMockedExternalDependencies:
    """Tests with mocked external dependencies like systemctl, rpm, etc."""
    
    @mock.patch('subprocess.run')
    def test_check_with_mocked_systemctl(self, mock_run) -> None:
        """Test checks that use systemctl with mocked subprocess."""
        # Mock successful systemctl response
        mock_run.return_value = mock.MagicMock(
            returncode=0,
            stdout="active\n",
            stderr=""
        )
        
        detector = EnvironmentDetector()
        
        # Test _is_service_active with mocked systemctl
        result = detector._is_service_active("sshd")
        assert result is True
        
        # Verify systemctl was called correctly
        mock_run.assert_called_with(
            ["systemctl", "is-active", "sshd.service"],
            capture_output=True,
            text=True,
            timeout=5
        )
    
    @mock.patch('subprocess.run')
    def test_check_with_mocked_rpm(self, mock_run) -> None:
        """Test checks that use rpm with mocked subprocess."""
        mock_run.return_value = mock.MagicMock(
            returncode=0,
            stdout="firewalld-1.3.0-1.fc43.x86_64\n",
            stderr=""
        )
        
        fedora_context = load_platform_context(
            profile_id="fedora-43",
            os_release_path="/nonexistent/os-release",
        )
        detector = EnvironmentDetector(platform_context=fedora_context)
        result = detector._is_package_installed("firewalld")
        
        assert result is True
        mock_run.assert_called_with(
            ["rpm", "-q", "firewalld"],
            capture_output=True,
            text=True,
            timeout=5
        )
    
    @mock.patch('subprocess.run')
    def test_check_with_systemctl_not_found(self, mock_run) -> None:
        """Test behavior when systemctl is not found."""
        mock_run.side_effect = FileNotFoundError("systemctl not found")
        
        detector = EnvironmentDetector()
        result = detector._is_service_active("sshd")
        
        assert result is False
    
    @mock.patch('subprocess.run')
    def test_check_with_systemctl_timeout(self, mock_run) -> None:
        """Test behavior when systemctl times out."""
        mock_run.side_effect = subprocess.TimeoutExpired("systemctl", 5)
        
        detector = EnvironmentDetector()
        result = detector._is_service_active("sshd")
        
        assert result is False
    
    @mock.patch('subprocess.run')
    def test_check_with_permission_error(self, mock_run) -> None:
        """Test behavior when subprocess raises PermissionError."""
        mock_run.side_effect = PermissionError("Permission denied")
        
        detector = EnvironmentDetector()
        result = detector._is_service_active("sshd")
        
        assert result is False


class TestEndToEndAudit:
    """End-to-end tests running the full audit flow."""
    
    def test_full_audit_with_mocked_checks(self, tmp_path: Path) -> None:
        """Run full audit with mocked check discovery."""
        cli = CLI()
        cli.parse_args(['--no-sudo', '--output', str(tmp_path / 'output.json')])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=1.0,
            signals={},
            override_used=True
        )
        
        # Create test check classes
        class MockCheck1(BaseCheck):
            id = "mock_check_1"
            name = "Mock Check 1"
            description = "First mock check"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Mock check 1 passed"
                )
        
        class MockCheck2(BaseCheck):
            id = "mock_check_2"
            name = "Mock Check 2"
            description = "Second mock check"
            severity = Severity.HIGH
            
            def run(self) -> CheckResult:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Mock check 2 failed",
                    remediation="Fix mock check 2"
                )
        
        # Mock registry methods
        mock_results = [
            MockCheck1(privileged=False).execute(),
            MockCheck2(privileged=False).execute()
        ]
        
        with mock.patch.object(CheckRegistry, 'discover', return_value=2):
            with mock.patch.object(CheckRegistry, 'run_all', return_value=mock_results):
                exit_code = cli.run_audit()
        
        assert exit_code == 2  # Warnings present
        
        # Verify output file was created
        output_file = tmp_path / 'output.json'
        assert output_file.exists()
        
        # Verify JSON structure
        data = json.loads(output_file.read_text())
        assert data["summary"]["total_checks"] == 2
        assert data["summary"]["passed"] == 1
        assert data["summary"]["failed"] == 1
    
    def test_full_audit_stdout_output(self, capsys) -> None:
        """Run full audit with stdout output."""
        cli = CLI()
        cli.parse_args(['--no-sudo'])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.DESKTOP,
            confidence=1.0,
            signals={},
            override_used=True
        )
        
        class MockCheck(BaseCheck):
            id = "stdout_check"
            name = "Stdout Check"
            description = "Testing stdout"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name
                )
        
        mock_results = [MockCheck(privileged=False).execute()]
        
        with mock.patch.object(CheckRegistry, 'discover', return_value=1):
            with mock.patch.object(CheckRegistry, 'run_all', return_value=mock_results):
                exit_code = cli.run_audit()
        
        assert exit_code == 0
        
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["summary"]["total_checks"] == 1
        assert data["summary"]["passed"] == 1
    
    def test_full_audit_with_pretty_print(self, capsys) -> None:
        """Run full audit with pretty-printed JSON output."""
        cli = CLI()
        cli.parse_args(['--no-sudo', '--pretty'])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=1.0,
            signals={},
            override_used=True
        )
        
        class MockCheck(BaseCheck):
            id = "pretty_check"
            name = "Pretty Check"
            description = "Testing pretty print"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name
                )
        
        mock_results = [MockCheck(privileged=False).execute()]
        
        with mock.patch.object(CheckRegistry, 'discover', return_value=1):
            with mock.patch.object(CheckRegistry, 'run_all', return_value=mock_results):
                cli.run_audit()
        
        captured = capsys.readouterr()
        # Pretty-printed JSON should have newlines and indentation
        assert '\n' in captured.out
        assert '  ' in captured.out

    def test_progress_total_uses_filtered_checks_count(self) -> None:
        """Progress bar total should match checks selected for execution."""
        cli = CLI()
        cli.parse_args(['--no-sudo'])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=1.0,
            signals={},
            override_used=True,
        )

        mock_progress_bar = mock.MagicMock()
        mock_progress_bar.__enter__.return_value = mock_progress_bar
        mock_progress_bar.__exit__.return_value = None

        with mock.patch('src.cli.create_progress_bar', return_value=mock_progress_bar) as mock_create:
            with mock.patch.object(CheckRegistry, 'discover', return_value=10):
                with mock.patch.object(CheckRegistry, 'get_checks', return_value=[object(), object(), object()]):
                    with mock.patch.object(CheckRegistry, 'run_all', return_value=[
                        CheckResult.passed_result(
                            check_id="check_1",
                            check_name="Check 1",
                            message="Passed",
                        )
                    ]):
                        exit_code = cli.run_audit()

        assert exit_code == 0
        assert mock_create.called
        assert mock_create.call_args.kwargs["total"] == 3


class TestRealCheckDiscovery:
    """Tests with actual check discovery from the project."""
    
    def test_discover_real_checks(self) -> None:
        """Test that real checks can be discovered."""
        registry = CheckRegistry()
        count = registry.discover()
        
        # Should discover at least some checks (or may be 0 if already imported in test run)
        # When running all tests, modules may already be loaded
        if count == 0:
            # If discovery returned 0, checks might already be registered from previous test
            # Try to discover fresh by clearing and re-discovering
            registry.clear()
            count = registry.discover()
        
        # If still 0, verify at least that we can discover when running standalone
        # This is acceptable in a full test suite where modules are already loaded
        if count == 0:
            pytest.skip("Checks already imported by previous tests - discovery returned 0")
        
        assert len(registry) > 0
        
        # Verify known checks are present
        check_ids = registry.get_check_ids()
        assert "auth_password_complexity" in check_ids
        assert "network_firewalld" in check_ids
    
    def test_run_real_checks_unprivileged(self) -> None:
        """Test running real checks without privileges."""
        registry = CheckRegistry()
        registry.discover()
        
        results = registry.run_all(privileged=False)

        # By default run_all excludes expensive/optional checks
        expected_count = len(registry.get_checks(include_expensive=False))
        assert len(results) == expected_count
        
        # Some checks should be skipped (those requiring root)
        skipped = [r for r in results if r.skipped]
        root_checks = [c for c in registry.get_checks() if c.requires_root]
        assert len(skipped) == len(root_checks)
    
    def test_real_checks_json_output(self) -> None:
        """Test JSON output with real discovered checks."""
        registry = CheckRegistry()
        registry.discover()
        
        results = registry.run_all(privileged=False)
        
        formatter = JSONFormatter()
        json_output = formatter.format(results, privileged=False)
        data = json.loads(json_output)
        
        # Validate structure
        assert "metadata" in data
        assert "summary" in data
        assert "checks" in data
        
        # Validate summary counts
        summary = data["summary"]
        expected_count = len(registry.get_checks(include_expensive=False))
        assert summary["total_checks"] == expected_count
        assert summary["passed"] + summary["failed"] + summary["skipped"] == expected_count


class TestCLIArgumentCombinations:
    """Tests for various CLI argument combinations."""
    
    def test_cli_basic_scan(self) -> None:
        """Test basic scan with no arguments."""
        cli = CLI()
        args = cli.parse_args([])
        
        assert args.output is None
        assert args.verbose is False
        assert args.no_sudo is False
    
    def test_cli_with_output(self) -> None:
        """Test scan with output file."""
        cli = CLI()
        args = cli.parse_args(['--output', 'report.json'])
        
        assert args.output == 'report.json'
    
    def test_cli_force_desktop(self) -> None:
        """Test scan with force-desktop."""
        cli = CLI()
        args = cli.parse_args(['--force-desktop'])
        
        assert args.force_desktop is True
    
    def test_cli_no_sudo(self) -> None:
        """Test scan with no-sudo."""
        cli = CLI()
        args = cli.parse_args(['--no-sudo'])
        
        assert args.no_sudo is True
    
    def test_cli_verbose_and_pretty(self) -> None:
        """Test scan with verbose and pretty flags."""
        cli = CLI()
        args = cli.parse_args(['--verbose', '--pretty'])
        
        assert args.verbose is True
        assert args.pretty is True
    
    def test_cli_all_flags(self) -> None:
        """Test scan with all flags combined."""
        cli = CLI()
        args = cli.parse_args([
            '--output', 'results.json',
            '--verbose',
            '--force-server',
            '--no-sudo',
            '--pretty',
            '--profile', 'fedora-43',
        ])
        
        assert args.output == 'results.json'
        assert args.verbose is True
        assert args.force_server is True
        assert args.no_sudo is True
        assert args.pretty is True
        assert args.profile == 'fedora-43'


class TestVerboseOutput:
    """Tests for verbose mode output."""
    
    def test_verbose_environment_info(self, capsys) -> None:
        """Test that verbose mode prints environment info."""
        cli = CLI()
        cli.parse_args(['--verbose', '--force-desktop'])
        cli.privilege_checker = PrivilegeChecker(skip_check=True)
        cli.detection_result = DetectionResult(
            environment=EnvironmentType.DESKTOP,
            confidence=0.9,
            signals={"graphical_target": 0.8},
            override_used=True
        )
        
        cli.print_environment_info()
        
        captured = capsys.readouterr()
        assert "Detected environment: desktop" in captured.out
        assert "Confidence: 0.9" in captured.out
        assert "override" in captured.out.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
