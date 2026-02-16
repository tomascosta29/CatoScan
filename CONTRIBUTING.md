# Contributing to CIS Audit Tool for Fedora 43

Thank you for your interest in contributing to the CIS Audit Tool! This guide will help you get started with development, understand our code style, and learn how to add new checks and features.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Code Style](#code-style)
- [How to Add a New Check](#how-to-add-a-new-check)
- [How to Add a New Output Formatter](#how-to-add-a-new-output-formatter)
- [Testing Requirements](#testing-requirements)
- [Example Check Template](#example-check-template)

## Development Environment Setup

### Prerequisites

- **Python**: 3.11 or higher
- **Operating System**: Fedora 43 (for full testing)
- **Git**: For version control

### Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd cis-audit-f43

# Verify Python version
python3 --version  # Should be 3.11+

# Run the test suite to verify setup
python3 -m pytest tests/ -v
```

### Project Structure

```
cis-audit-f43/
├── cis-audit.py              # Main executable entry point
├── README.md                 # User documentation
├── DESIGN.md                 # Architecture documentation
├── CONTRIBUTING.md           # This file
├── ROADMAP.md                # Project roadmap
├── src/
│   ├── __init__.py
│   ├── cli.py                # CLI argument parsing and main flow
│   ├── core/
│   │   ├── __init__.py
│   │   ├── check.py          # BaseCheck class and CheckResult
│   │   ├── detector.py       # Environment detection engine
│   │   └── registry.py       # Check auto-discovery and registry
│   ├── checks/               # Individual CIS check implementations
│   │   ├── __init__.py
│   │   ├── auth_*.py         # Authentication checks
│   │   ├── logging_*.py      # Logging checks
│   │   ├── network_*.py      # Network checks
│   │   └── fs_*.py           # Filesystem checks
│   └── output/
│       ├── __init__.py
│       └── json_formatter.py # JSON output formatting
└── tests/
    ├── test_detector.py      # Environment detection tests
    ├── test_check_framework.py  # Check framework tests
    ├── test_json_formatter.py   # JSON formatter tests
    └── test_integration.py   # Integration tests
```

## Code Style

We follow **PEP 8** with some project-specific conventions.

### General Guidelines

- **Line Length**: 100 characters maximum
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Use double quotes for strings, single quotes for dict keys when needed
- **Imports**: Group imports: stdlib, third-party, local; sort alphabetically within groups

### Type Hints

All functions must include type hints:

```python
def process_results(results: list[CheckResult]) -> dict[str, Any]:
    """Process check results and return summary.
    
    Args:
        results: List of check results from the audit
        
    Returns:
        Dictionary containing summary statistics
    """
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def run_check(self, check_id: str, privileged: bool = False) -> CheckResult:
    """Execute a single check by id.
    
    Args:
        check_id: The unique identifier of the check to run
        privileged: Whether the check should run with root privileges
        
    Returns:
        CheckResult from the check execution
        
    Raises:
        KeyError: If the check_id is not registered
    """
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `PasswordComplexityCheck`)
- **Functions/Methods**: `snake_case` (e.g., `check_privileges`)
- **Variables**: `snake_case` (e.g., `check_result`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `PAM_CONFIG_FILES`)
- **Check IDs**: `lowercase_with_underscores` (e.g., `auth_password_complexity`)

### Check ID Naming Convention

Check IDs follow the pattern: `category_specific_name`

**Categories:**
- `auth_*`: Authentication and authorization
- `logging_*`: Logging and auditing
- `network_*`: Network security
- `fs_*`: Filesystem and permissions
- `kernel_*`: Kernel parameters (future)
- `services_*`: Service configuration (future)

**Examples:**
- `auth_password_complexity`
- `logging_rsyslog`
- `network_firewalld`
- `fs_tmp_mount`

## How to Add a New Check

Follow these steps to add a new CIS check to the tool.

### Step 1: Create File in `src/checks/`

Create a new Python file with a descriptive name:

```bash
touch src/checks/auth_ssh_ciphers.py
```

### Step 2: Inherit from `BaseCheck`

```python
"""CIS Audit Check: SSH Cipher Configuration

Verifies that SSH is configured to use strong ciphers only.
"""

from src.core.check import BaseCheck, CheckResult, Severity


class SSHCipherCheck(BaseCheck):
    """Check for SSH cipher configuration."""
    
    id = "auth_ssh_ciphers"
    name = "SSH Strong Ciphers"
    description = "Verifies SSH is configured to use strong ciphers only"
    severity = Severity.HIGH
    requires_root = True
    
    SSH_CONFIG = "/etc/ssh/sshd_config"
    
    def run(self) -> CheckResult:
        """Execute the SSH cipher check."""
        # Implementation here
        pass
```

### Step 3: Define Metadata

Required class attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | `str` | Unique identifier (lowercase with underscores) |
| `name` | `str` | Human-readable name |
| `description` | `str` | Detailed description of what the check does |
| `severity` | `Severity` | CRITICAL, HIGH, MEDIUM, or LOW |
| `requires_root` | `bool` | Whether root privileges are required |

### Step 4: Implement `run()` Method

The `run()` method contains the actual check logic:

```python
def run(self) -> CheckResult:
    """Execute the SSH cipher check.
    
    Returns:
        CheckResult with the outcome of the check
    """
    import os
    import re
    
    # Check if SSH config exists
    if not os.path.exists(self.SSH_CONFIG):
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"SSH configuration file not found: {self.SSH_CONFIG}",
            remediation="Ensure OpenSSH server is installed",
            severity=self.severity,
            requires_root=self.requires_root,
        )
    
    # Read SSH config
    try:
        with open(self.SSH_CONFIG, "r") as f:
            content = f.read()
    except (IOError, OSError) as e:
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Cannot read SSH configuration: {e}",
            remediation="Check file permissions",
            severity=self.severity,
            requires_root=self.requires_root,
        )
    
    # Check for Ciphers line
    cipher_line = None
    for line in content.split("\n"):
        if line.strip().startswith("Ciphers"):
            cipher_line = line.strip()
            break
    
    if not cipher_line:
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message="No Ciphers line found in sshd_config",
            remediation="Add 'Ciphers' configuration to /etc/ssh/sshd_config",
            severity=self.severity,
            requires_root=self.requires_root,
            details={"config_file": self.SSH_CONFIG},
        )
    
    # Check for weak ciphers
    weak_ciphers = ["3des-cbc", "blowfish-cbc", "arcfour"]
    found_weak = [c for c in weak_ciphers if c in cipher_line]
    
    if found_weak:
        return CheckResult.failed_result(
            check_id=self.id,
            check_name=self.name,
            message=f"Weak ciphers found: {', '.join(found_weak)}",
            remediation="Remove weak ciphers from Ciphers line in sshd_config",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "cipher_line": cipher_line,
                "weak_ciphers": found_weak,
            },
        )
    
    return CheckResult.passed_result(
        check_id=self.id,
        check_name=self.name,
        message="SSH is configured with strong ciphers only",
        severity=self.severity,
        requires_root=self.requires_root,
        details={"cipher_line": cipher_line},
    )
```

### Step 5: Add to `__init__.py`

Export your check from `src/checks/__init__.py`:

```python
# Add to imports
from src.checks.auth_ssh_ciphers import SSHCipherCheck

# Add to __all__
__all__ = [
    # ... existing exports ...
    "SSHCipherCheck",
]
```

### Step 6: Write Tests

Create tests in `tests/test_check_framework.py` or a new test file:

```python
class TestSSHCipherCheck:
    """Tests for SSH cipher check."""
    
    def test_check_metadata(self):
        """Test check has correct metadata."""
        from src.checks.auth_ssh_ciphers import SSHCipherCheck
        
        assert SSHCipherCheck.id == "auth_ssh_ciphers"
        assert SSHCipherCheck.name == "SSH Strong Ciphers"
        assert SSHCipherCheck.severity == Severity.HIGH
        assert SSHCipherCheck.requires_root is True
    
    @mock.patch("os.path.exists")
    def test_missing_config(self, mock_exists):
        """Test check fails when config is missing."""
        mock_exists.return_value = False
        
        check = SSHCipherCheck(privileged=True)
        result = check.run()
        
        assert result.passed is False
        assert "not found" in result.message
    
    @mock.patch("builtins.open", mock.mock_open(read_data="Ciphers aes256-gcm@openssh.com"))
    @mock.patch("os.path.exists")
    def test_strong_ciphers(self, mock_exists):
        """Test check passes with strong ciphers."""
        mock_exists.return_value = True
        
        check = SSHCipherCheck(privileged=True)
        result = check.run()
        
        assert result.passed is True
```

Run your tests:

```bash
python3 -m pytest tests/test_check_framework.py::TestSSHCipherCheck -v
```

## How to Add a New Output Formatter

### 1. Create Formatter Class

```python
# src/output/markdown_formatter.py
"""Markdown output formatter for CIS audit results."""

from datetime import datetime, timezone
from typing import Any, Optional
from pathlib import Path

from ..core.check import CheckResult, Severity
from ..core.detector import DetectionResult


class MarkdownFormatter:
    """Formatter for CIS audit results in Markdown format."""
    
    def __init__(self, include_details: bool = True) -> None:
        """Initialize the Markdown formatter.
        
        Args:
            include_details: Whether to include detailed check output
        """
        self._include_details = include_details
    
    def format(
        self,
        results: list[CheckResult],
        detection_result: Optional[DetectionResult] = None,
        privileged: bool = False
    ) -> str:
        """Format check results as Markdown.
        
        Args:
            results: List of CheckResult objects
            detection_result: Optional environment detection result
            privileged: Whether the audit ran with root privileges
            
        Returns:
            Markdown-formatted string
        """
        lines = []
        
        # Header
        lines.append("# CIS Audit Report\n")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n")
        
        # Summary
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed and not r.skipped)
        skipped = sum(1 for r in results if r.skipped)
        
        lines.append("## Summary\n")
        lines.append(f"- **Total Checks:** {len(results)}")
        lines.append(f"- **Passed:** {passed} ✅")
        lines.append(f"- **Failed:** {failed} ❌")
        lines.append(f"- **Skipped:** {skipped} ⏭️")
        lines.append("")
        
        # Checks
        lines.append("## Check Results\n")
        
        for result in results:
            status_icon = "✅" if result.passed else "❌" if not result.skipped else "⏭️"
            lines.append(f"### {status_icon} {result.check_name}\n")
            lines.append(f"**ID:** `{result.check_id}`")
            lines.append(f"**Severity:** {result.severity.value.upper()}")
            lines.append(f"**Status:** {'Passed' if result.passed else 'Failed' if not result.skipped else 'Skipped'}")
            lines.append("")
            lines.append(f"{result.message}")
            
            if result.remediation:
                lines.append("")
                lines.append("**Remediation:**")
                lines.append(f"```")
                lines.append(result.remediation)
                lines.append(f"```")
            
            if self._include_details and result.details:
                lines.append("")
                lines.append("**Details:**")
                lines.append(f"```json")
                import json
                lines.append(json.dumps(result.details, indent=2))
                lines.append(f"```")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def write_to_file(
        self,
        results: list[CheckResult],
        output_path: Path,
        detection_result: Optional[DetectionResult] = None,
        privileged: bool = False
    ) -> None:
        """Write formatted Markdown to a file."""
        content = self.format(results, detection_result, privileged)
        output_path.write_text(content, encoding="utf-8")
```

### 2. Export Formatter

```python
# src/output/__init__.py
from .json_formatter import JSONFormatter, DateTimeEncoder
from .markdown_formatter import MarkdownFormatter

__all__ = ["JSONFormatter", "DateTimeEncoder", "MarkdownFormatter"]
```

### 3. Add CLI Option (Optional)

To allow users to select the formatter:

```python
# In src/cli.py
parser.add_argument(
    "--format",
    choices=["json", "markdown"],
    default="json",
    help="Output format"
)

# In run_audit method
if self.args.format == "markdown":
    formatter = MarkdownFormatter()
else:
    formatter = JSONFormatter(pretty=self.args.pretty)
```

## Testing Requirements

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_detector.py -v

# Run specific test class
python3 -m pytest tests/test_integration.py::TestCLIArgumentParsing -v

# Run with coverage
python3 -m pytest tests/ --cov=src --cov-report=html
```

### Test Coverage Requirements

- **Minimum Coverage**: 80% for new code
- **Critical Paths**: 100% coverage for privilege handling and result formatting
- **Check Implementations**: Each check must have unit tests

### Writing Good Tests

1. **Test One Thing**: Each test should verify one behavior
2. **Use Descriptive Names**: Test names should describe what's being tested
3. **Mock External Dependencies**: Use `@mock.patch` for system calls
4. **Test Edge Cases**: Include tests for missing files, permission errors, etc.

### Example Test Patterns

```python
class TestMyCheck:
    """Tests for MyCheck."""
    
    def test_metadata(self):
        """Test check has required metadata."""
        assert MyCheck.id == "category_check_name"
        assert MyCheck.name == "Human Readable Name"
        assert MyCheck.severity == Severity.HIGH
    
    @mock.patch("os.path.exists")
    def test_missing_file(self, mock_exists):
        """Test behavior when required file is missing."""
        mock_exists.return_value = False
        
        check = MyCheck(privileged=True)
        result = check.run()
        
        assert result.passed is False
        assert "not found" in result.message.lower()
    
    @mock.patch("builtins.open", mock.mock_open(read_data="config content"))
    @mock.patch("os.path.exists")
    def test_passing_configuration(self, mock_exists):
        """Test check passes with correct configuration."""
        mock_exists.return_value = True
        
        check = MyCheck(privileged=True)
        result = check.run()
        
        assert result.passed is True
    
    def test_skipped_without_privileges(self):
        """Test check is skipped when requires_root=True and not privileged."""
        check = MyCheck(privileged=False)
        result = check.execute()  # Use execute(), not run()
        
        assert result.skipped is True
        assert result.passed is False
```

## Example Check Template

Use this template as a starting point for new checks:

```python
"""CIS Audit Check: [Brief Description]

[Detailed description of what this check does and why it matters
for security. Reference CIS benchmark section if applicable.]

CIS Benchmark: [Section Number] - [Title]
"""

import os
import re
from pathlib import Path
from typing import Optional

from src.core.check import BaseCheck, CheckResult, Severity


class [CheckName]Check(BaseCheck):
    """[One-line description of the check.]
    
    [Optional: Additional context about the check's purpose,
    what it looks for, and how it determines pass/fail.]
    """
    
    # Check metadata
    id = "category_check_name"  # lowercase_with_underscores
    name = "[Human-Readable Check Name]"
    description = (
        "[Detailed description of what this check validates. "
        "This should be 1-2 sentences explaining the security concern.]"
    )
    severity = Severity.MEDIUM  # CRITICAL, HIGH, MEDIUM, or LOW
    requires_root = False  # Set True if check needs root privileges
    
    # Configuration constants
    CONFIG_FILE = "/etc/path/to/config"
    EXPECTED_VALUE = "expected"
    
    def run(self) -> CheckResult:
        """Execute the check.
        
        Returns:
            CheckResult with the outcome of the check
        """
        # Step 1: Check prerequisites (file exists, readable, etc.)
        if not os.path.exists(self.CONFIG_FILE):
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Configuration file not found: {self.CONFIG_FILE}",
                remediation=f"Ensure the configuration file exists at {self.CONFIG_FILE}",
                severity=self.severity,
                requires_root=self.requires_root,
            )
        
        # Step 2: Read and parse configuration
        try:
            config_content = Path(self.CONFIG_FILE).read_text()
        except (IOError, OSError) as e:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Cannot read configuration file: {e}",
                remediation="Check file permissions and ensure the file is readable",
                severity=self.severity,
                requires_root=self.requires_root,
            )
        
        # Step 3: Validate configuration
        current_value = self._extract_value(config_content)
        
        if current_value is None:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Required configuration not found",
                remediation=f"Add the required configuration to {self.CONFIG_FILE}",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"config_file": self.CONFIG_FILE},
            )
        
        if current_value != self.EXPECTED_VALUE:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message=f"Incorrect configuration: found '{current_value}', expected '{self.EXPECTED_VALUE}'",
                remediation=f"Update {self.CONFIG_FILE} to set the correct value",
                severity=self.severity,
                requires_root=self.requires_root,
                details={
                    "config_file": self.CONFIG_FILE,
                    "found_value": current_value,
                    "expected_value": self.EXPECTED_VALUE,
                },
            )
        
        # Step 4: Return success
        return CheckResult.passed_result(
            check_id=self.id,
            check_name=self.name,
            message="Configuration is correct",
            severity=self.severity,
            requires_root=self.requires_root,
            details={
                "config_file": self.CONFIG_FILE,
                "value": current_value,
            },
        )
    
    def _extract_value(self, content: str) -> Optional[str]:
        """Extract the configuration value from file content.
        
        Args:
            content: The configuration file content
            
        Returns:
            The extracted value or None if not found
        """
        # Implement value extraction logic
        # Example: regex matching, line parsing, etc.
        for line in content.split("\n"):
            if line.strip().startswith("CONFIG_KEY"):
                parts = line.split("=")
                if len(parts) >= 2:
                    return parts[1].strip().strip('"\'')
        return None
```

## Submitting Contributions

1. **Fork and Branch**: Create a feature branch from `main`
2. **Write Tests**: Add tests for new functionality
3. **Run Tests**: Ensure all tests pass
4. **Update Documentation**: Update README.md if adding new checks
5. **Submit PR**: Create a pull request with clear description

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] Check ID follows naming convention
- [ ] Severity level appropriate for the issue
- [ ] Remediation instructions are clear and actionable

## Questions?

If you have questions about contributing:

1. Check existing checks in `src/checks/` for examples
2. Review the test files for testing patterns
3. Open an issue for discussion before major changes

Thank you for contributing to CIS Audit Tool for Fedora 43!
