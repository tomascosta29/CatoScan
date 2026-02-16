"""
CIS Audit Tool for Fedora 43 - Check Framework Tests

Integration tests for the check framework, registry, and base classes.
"""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.check import BaseCheck, CheckResult, Severity
from src.core.registry import CheckRegistry


class TestSeverity:
    """Tests for the Severity enum."""
    
    def test_severity_values(self) -> None:
        """Test that Severity enum has expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
    
    def test_severity_comparison(self) -> None:
        """Test severity ordering."""
        # Severity enum order: CRITICAL, HIGH, MEDIUM, LOW
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        assert severities == sorted(severities, key=lambda s: list(Severity).index(s))


class TestCheckResult:
    """Tests for the CheckResult dataclass."""
    
    def test_basic_result_creation(self) -> None:
        """Test creating a basic CheckResult."""
        result = CheckResult(
            check_id="test_check",
            check_name="Test Check",
            passed=True,
            message="Test passed",
            severity=Severity.HIGH,
        )
        assert result.check_id == "test_check"
        assert result.check_name == "Test Check"
        assert result.passed is True
        assert result.skipped is False
        assert result.message == "Test passed"
        assert result.severity == Severity.HIGH
    
    def test_result_validation_empty_id(self) -> None:
        """Test that empty check_id raises ValueError."""
        with pytest.raises(ValueError, match="check_id cannot be empty"):
            CheckResult(check_id="", check_name="Test", passed=True)
    
    def test_result_validation_empty_name(self) -> None:
        """Test that empty check_name raises ValueError."""
        with pytest.raises(ValueError, match="check_name cannot be empty"):
            CheckResult(check_id="test", check_name="", passed=True)
    
    def test_result_validation_skipped_and_passed(self) -> None:
        """Test that skipped=True with passed=True raises ValueError."""
        with pytest.raises(ValueError, match="skipped check cannot be marked as passed"):
            CheckResult(
                check_id="test",
                check_name="Test",
                passed=True,
                skipped=True
            )
    
    def test_passed_result_factory(self) -> None:
        """Test the passed_result factory method."""
        result = CheckResult.passed_result(
            check_id="test_id",
            check_name="Test Name",
            message="All good",
            severity=Severity.LOW
        )
        assert result.passed is True
        assert result.skipped is False
        assert result.check_id == "test_id"
        assert result.message == "All good"
        assert result.remediation == ""
    
    def test_failed_result_factory(self) -> None:
        """Test the failed_result factory method."""
        result = CheckResult.failed_result(
            check_id="test_id",
            check_name="Test Name",
            message="Something failed",
            remediation="Fix it by doing X",
            severity=Severity.CRITICAL
        )
        assert result.passed is False
        assert result.skipped is False
        assert result.message == "Something failed"
        assert result.remediation == "Fix it by doing X"
    
    def test_skipped_result_factory(self) -> None:
        """Test the skipped_result factory method."""
        result = CheckResult.skipped_result(
            check_id="test_id",
            check_name="Test Name",
            message="No privileges"
        )
        assert result.passed is False
        assert result.skipped is True
        assert "No privileges" in result.message
        assert "sudo" in result.remediation.lower()
    
    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        result = CheckResult(
            check_id="test",
            check_name="Test",
            passed=True,
            severity=Severity.HIGH,
            details={"key": "value"}
        )
        d = result.to_dict()
        assert d["check_id"] == "test"
        assert d["passed"] is True
        assert d["severity"] == "high"
        assert d["details"] == {"key": "value"}


class TestBaseCheck:
    """Tests for the BaseCheck abstract class."""
    
    def test_valid_check_subclass(self) -> None:
        """Test creating a valid check subclass."""
        class ValidCheck(BaseCheck):
            id = "test_valid"
            name = "Valid Test Check"
            description = "A valid test check"
            severity = Severity.MEDIUM
            requires_root = False
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name
                )
        
        # Should not raise
        check = ValidCheck(privileged=False)
        assert check.id == "test_valid"
        assert check.name == "Valid Test Check"
        assert check.privileged is False
    
    def test_missing_id_raises(self) -> None:
        """Test that missing id raises ValueError."""
        with pytest.raises(ValueError, match="must define 'id'"):
            class BadCheck(BaseCheck):
                name = "Bad Check"
                description = "Missing id"
                
                def run(self) -> CheckResult:
                    return CheckResult.passed_result(check_id="", check_name="")
    
    def test_missing_name_raises(self) -> None:
        """Test that missing name raises ValueError."""
        with pytest.raises(ValueError, match="must define 'name'"):
            class BadCheck(BaseCheck):
                id = "bad_check"
                description = "Missing name"
                
                def run(self) -> CheckResult:
                    return CheckResult.passed_result(check_id="", check_name="")
    
    def test_missing_description_raises(self) -> None:
        """Test that missing description raises ValueError."""
        with pytest.raises(ValueError, match="must define 'description'"):
            class BadCheck(BaseCheck):
                id = "bad_check"
                name = "Bad Check"
                
                def run(self) -> CheckResult:
                    return CheckResult.passed_result(check_id="", check_name="")
    
    def test_invalid_id_format(self) -> None:
        """Test that invalid id format raises ValueError."""
        with pytest.raises(ValueError, match="lowercase alphanumeric"):
            class BadCheck(BaseCheck):
                id = "Bad-Check-ID"  # Invalid: uppercase and hyphen
                name = "Bad Check"
                description = "Invalid id format"
                
                def run(self) -> CheckResult:
                    return CheckResult.passed_result(check_id="", check_name="")
    
    def test_should_skip_unprivileged(self) -> None:
        """Test should_skip when unprivileged and check requires root."""
        class RootCheck(BaseCheck):
            id = "root_check"
            name = "Root Check"
            description = "Requires root"
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        check = RootCheck(privileged=False)
        assert check.should_skip() is True
    
    def test_should_not_skip_privileged(self) -> None:
        """Test should_skip when privileged and check requires root."""
        class RootCheck(BaseCheck):
            id = "root_check"
            name = "Root Check"
            description = "Requires root"
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        check = RootCheck(privileged=True)
        assert check.should_skip() is False
    
    def test_should_not_skip_unprivileged_check(self) -> None:
        """Test should_skip when check doesn't require root."""
        class UserCheck(BaseCheck):
            id = "user_check"
            name = "User Check"
            description = "Does not require root"
            requires_root = False
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        check = UserCheck(privileged=False)
        assert check.should_skip() is False
    
    def test_execute_runs_check(self) -> None:
        """Test that execute() runs the check when not skipped."""
        class PassCheck(BaseCheck):
            id = "pass_check"
            name = "Pass Check"
            description = "Always passes"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Passed!"
                )
        
        check = PassCheck(privileged=False)
        result = check.execute()
        assert result.passed is True
        assert result.message == "Passed!"
    
    def test_execute_skips_check(self) -> None:
        """Test that execute() returns skip result when should_skip is True."""
        class RootCheck(BaseCheck):
            id = "root_check"
            name = "Root Check"
            description = "Requires root"
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        check = RootCheck(privileged=False)
        result = check.execute()
        assert result.skipped is True
        assert result.passed is False
    
    def test_execute_handles_exception(self) -> None:
        """Test that execute() handles exceptions gracefully."""
        class FailCheck(BaseCheck):
            id = "fail_check"
            name = "Fail Check"
            description = "Always fails"
            
            def run(self) -> CheckResult:
                raise RuntimeError("Something went wrong")
        
        check = FailCheck(privileged=False)
        result = check.execute()
        assert result.passed is False
        assert result.skipped is False
        assert "error" in result.message.lower()
        assert result.details.get("error_type") == "RuntimeError"
    
    def test_get_metadata(self) -> None:
        """Test getting check metadata."""
        class MetaCheck(BaseCheck):
            id = "meta_check"
            name = "Meta Check"
            description = "Returns metadata"
            severity = Severity.HIGH
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        check = MetaCheck(privileged=True)
        meta = check.get_metadata()
        assert meta["id"] == "meta_check"
        assert meta["name"] == "Meta Check"
        assert meta["severity"] == "high"
        assert meta["requires_root"] is True


class TestCheckRegistry:
    """Tests for the CheckRegistry class."""
    
    def test_empty_registry(self) -> None:
        """Test that a new registry is empty."""
        registry = CheckRegistry()
        assert len(registry) == 0
        assert registry.get_checks() == []
    
    def test_register_check(self) -> None:
        """Test registering a check class."""
        registry = CheckRegistry()
        
        class TestCheck(BaseCheck):
            id = "test_register"
            name = "Test Register"
            description = "Test registration"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(TestCheck)
        assert len(registry) == 1
        assert "test_register" in registry
        assert registry.get_check("test_register") == TestCheck
    
    def test_register_non_class_raises(self) -> None:
        """Test that registering a non-class raises TypeError."""
        registry = CheckRegistry()
        with pytest.raises(TypeError, match="Expected a class"):
            registry.register("not a class")  # type: ignore
    
    def test_register_non_basecheck_raises(self) -> None:
        """Test that registering a non-BaseCheck class raises TypeError."""
        registry = CheckRegistry()
        
        class NotACheck:
            pass
        
        with pytest.raises(TypeError, match="must inherit from BaseCheck"):
            registry.register(NotACheck)  # type: ignore
    
    def test_register_duplicate_raises(self) -> None:
        """Test that registering a duplicate check id raises ValueError."""
        registry = CheckRegistry()
        
        class TestCheck1(BaseCheck):
            id = "duplicate_id"
            name = "Test 1"
            description = "First"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        class TestCheck2(BaseCheck):
            id = "duplicate_id"
            name = "Test 2"
            description = "Second"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(TestCheck1)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(TestCheck2)
    
    def test_unregister(self) -> None:
        """Test unregistering a check."""
        registry = CheckRegistry()
        
        class TestCheck(BaseCheck):
            id = "to_remove"
            name = "To Remove"
            description = "Will be removed"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(TestCheck)
        assert len(registry) == 1
        
        registry.unregister("to_remove")
        assert len(registry) == 0
        assert "to_remove" not in registry
    
    def test_unregister_unknown_raises(self) -> None:
        """Test that unregistering an unknown check raises KeyError."""
        registry = CheckRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.unregister("unknown")
    
    def test_get_checks_filter_by_root(self) -> None:
        """Test filtering checks by requires_root."""
        registry = CheckRegistry()
        
        class UserCheck(BaseCheck):
            id = "user_check"
            name = "User Check"
            description = "No root needed"
            requires_root = False
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        class RootCheck(BaseCheck):
            id = "root_check"
            name = "Root Check"
            description = "Root needed"
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(UserCheck)
        registry.register(RootCheck)
        
        all_checks = registry.get_checks()
        assert len(all_checks) == 2
        
        user_checks = registry.get_checks(requires_root=False)
        assert len(user_checks) == 1
        assert user_checks[0].id == "user_check"
        
        root_checks = registry.get_checks(requires_root=True)
        assert len(root_checks) == 1
        assert root_checks[0].id == "root_check"
    
    def test_run_all(self) -> None:
        """Test running all checks."""
        registry = CheckRegistry()
        
        class PassCheck(BaseCheck):
            id = "pass_check"
            name = "Pass Check"
            description = "Passes"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        class FailCheck(BaseCheck):
            id = "fail_check"
            name = "Fail Check"
            description = "Fails"
            
            def run(self) -> CheckResult:
                return CheckResult.failed_result(
                    check_id=self.id,
                    check_name=self.name,
                    message="Failed"
                )
        
        registry.register(PassCheck)
        registry.register(FailCheck)
        
        results = registry.run_all(privileged=False)
        assert len(results) == 2
        
        passed = [r for r in results if r.passed]
        failed = [r for r in results if not r.passed and not r.skipped]
        assert len(passed) == 1
        assert len(failed) == 1
    
    def test_run_all_with_check_ids(self) -> None:
        """Test running specific check ids."""
        registry = CheckRegistry()
        
        class CheckA(BaseCheck):
            id = "check_a"
            name = "Check A"
            description = "A"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        class CheckB(BaseCheck):
            id = "check_b"
            name = "Check B"
            description = "B"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(CheckA)
        registry.register(CheckB)
        
        results = registry.run_all(privileged=False, check_ids=["check_a"])
        assert len(results) == 1
        assert results[0].check_id == "check_a"
    
    def test_run_all_unknown_check_id(self) -> None:
        """Test running with an unknown check id."""
        registry = CheckRegistry()
        
        results = registry.run_all(privileged=False, check_ids=["unknown"])
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].check_id == "unknown"
    
    def test_run_all_skips_root_checks_when_unprivileged(self) -> None:
        """Test that run_all skips root checks when not privileged."""
        registry = CheckRegistry()
        
        class RootCheck(BaseCheck):
            id = "root_check"
            name = "Root Check"
            description = "Needs root"
            requires_root = True
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(RootCheck)
        
        results = registry.run_all(privileged=False)
        assert len(results) == 1
        assert results[0].skipped is True
    
    def test_run_check(self) -> None:
        """Test running a single check by id."""
        registry = CheckRegistry()
        
        class TestCheck(BaseCheck):
            id = "single_check"
            name = "Single Check"
            description = "Single"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(TestCheck)
        
        result = registry.run_check("single_check", privileged=False)
        assert result.passed is True
        assert result.check_id == "single_check"
    
    def test_run_check_unknown_raises(self) -> None:
        """Test that running an unknown check raises KeyError."""
        registry = CheckRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.run_check("unknown", privileged=False)
    
    def test_clear(self) -> None:
        """Test clearing the registry."""
        registry = CheckRegistry()
        
        class TestCheck(BaseCheck):
            id = "to_clear"
            name = "To Clear"
            description = "Will be cleared"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(TestCheck)
        assert len(registry) == 1
        
        registry.clear()
        assert len(registry) == 0
    
    def test_get_check_ids(self) -> None:
        """Test getting all check ids."""
        registry = CheckRegistry()
        
        class CheckB(BaseCheck):
            id = "check_b"
            name = "Check B"
            description = "B"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        class CheckA(BaseCheck):
            id = "check_a"
            name = "Check A"
            description = "A"
            
            def run(self) -> CheckResult:
                return CheckResult.passed_result(check_id=self.id, check_name=self.name)
        
        registry.register(CheckB)
        registry.register(CheckA)
        
        ids = registry.get_check_ids()
        assert ids == ["check_a", "check_b"]  # Sorted


class TestCheckRegistryDiscovery:
    """Tests for check discovery functionality."""
    
    def test_discover_empty_directory(self) -> None:
        """Test discovery with empty/non-existent directory."""
        registry = CheckRegistry()
        count = registry.discover("/nonexistent/path")
        assert count == 0
    
    def test_discover_finds_checks(self, tmp_path: Path) -> None:
        """Test that discover finds check classes in modules."""
        # Create a temporary checks directory
        checks_dir = tmp_path / "checks"
        checks_dir.mkdir()
        
        # Create __init__.py
        (checks_dir / "__init__.py").write_text("")
        
        # Create a check module
        check_module = checks_dir / "test_check.py"
        check_module.write_text('''
from src.core.check import BaseCheck, CheckResult, Severity

class DiscoveredCheck(BaseCheck):
    id = "discovered_check"
    name = "Discovered Check"
    description = "Found by discovery"
    severity = Severity.MEDIUM
    requires_root = False
    
    def run(self) -> CheckResult:
        return CheckResult.passed_result(check_id=self.id, check_name=self.name)
''')
        
        # Create another module with abstract class (should not be registered)
        abstract_module = checks_dir / "abstract.py"
        abstract_module.write_text('''
from src.core.check import BaseCheck, CheckResult
from abc import abstractmethod

class AbstractCheck(BaseCheck):
    """Abstract check should not be registered."""
    id = "abstract_check"
    name = "Abstract Check"
    description = "Abstract"
    
    @abstractmethod
    def run(self) -> CheckResult:
        pass
''')
        
        registry = CheckRegistry()
        count = registry.discover(str(checks_dir))
        
        assert count == 1
        assert "discovered_check" in registry
        assert "abstract_check" not in registry

    def test_discover_records_module_import_errors(self, tmp_path: Path) -> None:
        """Test that discovery records import/module load failures."""
        checks_dir = tmp_path / "checks_import_error"
        checks_dir.mkdir()
        (checks_dir / "__init__.py").write_text("")

        # Valid check module (should still be discovered)
        (checks_dir / "good_check.py").write_text(
            '''
from src.core.check import BaseCheck, CheckResult

class GoodCheck(BaseCheck):
    id = "good_check"
    name = "Good Check"
    description = "A valid check"

    def run(self) -> CheckResult:
        return CheckResult.passed_result(check_id=self.id, check_name=self.name)
'''
        )

        # Broken module import (should be recorded as discovery error)
        (checks_dir / "broken_check.py").write_text(
            "import definitely_missing_module\n"
        )

        registry = CheckRegistry()
        count = registry.discover(str(checks_dir))

        assert count == 1
        assert "good_check" in registry
        assert registry.has_discovery_errors is True
        assert any("broken_check" in error for error in registry.discovery_errors)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
