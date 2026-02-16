# CatoScan

A read-only security audit tool that checks Linux systems against CIS (Center for Internet Security) benchmarks. The tool auto-detects desktop vs server environments, supports distro profiles, and produces structured JSON reports.

Current release: `3.5.0` (see `CHANGELOG.md`)

## Overview

This tool performs automated security checks based on CIS benchmarks. It examines system configurations across multiple categories including authentication, logging, network security, and filesystem permissions.

**Key Features:**
- 🔍 **Environment Detection**: Automatically detects desktop vs server environments
- 📊 **Structured Output**: JSON output for easy integration with other tools
- 🔒 **Read-Only**: Safe to run - makes no changes to your system
- 🏷️ **Check Categorization**: Organized by security domain (auth, logging, network, filesystem)
- ⚡ **Privilege Awareness**: Skips checks requiring root when run without sudo
- 📈 **Web Viewer**: Built-in HTML/JS viewer for visualizing audit results

## Requirements

- **Python**: 3.11 or higher
- **Operating System**: Linux with a supported profile (Fedora 43 default, Ubuntu 24.04 pilot)
- **Privileges**: Root/sudo recommended for full scan (some checks can run without)

## Profile Support Status

| Profile | Status | Notes |
|---------|--------|-------|
| `fedora-43` | Stable baseline | Primary compatibility target; full check coverage maintained |
| `ubuntu-24.04` | Pilot | Profile loading and command templating validated; full check parity still in progress |

### Ubuntu Pilot Caveats

- Command rendering is profile-aware for migrated checks, but some checks still assume Fedora package names or file layouts.
- `metadata.fedora_version` is still emitted for backward compatibility with existing consumers.
- Use `--profile ubuntu-24.04` for deterministic profile testing while rollout continues.

## Installation

1. Clone or download the repository:
```bash
git clone <repository-url>
cd CatoScan
```

2. Ensure Python 3.11+ is installed:
```bash
python3 --version
```

3. Make the script executable:
```bash
chmod +x catoscan.py
```

No additional Python packages are required - the tool uses only standard library modules.

## Usage

### Basic Scan

Run the audit with default settings:

```bash
sudo ./catoscan.py
```

This will:
- Auto-detect your environment (desktop/server)
- Run all applicable CIS checks
- Output JSON results to stdout

### With Output File

Save results to a JSON file:

```bash
sudo ./catoscan.py --output report.json
# or
sudo ./catoscan.py -o report.json
```

### Force Desktop Environment

Override auto-detection and force desktop mode:

```bash
sudo ./catoscan.py --force-desktop
```

### Override Platform Profile

Force a specific distro profile (useful for testing profile behavior):

```bash
sudo ./catoscan.py --profile fedora-43
sudo ./catoscan.py --profile ubuntu-24.04
```

### Run Without Sudo

Run without root privileges (some checks will be skipped):

```bash
./catoscan.py --no-sudo
```

### Pretty-Printed Output

Output formatted JSON with indentation:

```bash
sudo ./catoscan.py --pretty
```

### Verbose Mode

Show detailed progress information:

```bash
sudo ./catoscan.py --verbose
# or
sudo ./catoscan.py -v
```

### Combined Options

Multiple options can be combined:

```bash
sudo ./catoscan.py --verbose --pretty --output report.json
```

## Web Viewer

CatoScan includes a built-in web-based viewer for visualizing audit results. The viewer is a single-page application that runs entirely in your browser with no external dependencies.

### Opening the Viewer

Simply open the viewer HTML file in any modern web browser:

```bash
# From the project directory
firefox viewer/index.html
# or
chrome viewer/index.html
# or just double-click the file in your file manager
```

### Loading a Report

1. Click **"Load JSON Report"** or drag and drop a JSON file onto the page
2. The dashboard will display with:
   - Report metadata (hostname, timestamp, environment)
   - Summary cards showing total, passed, failed, and skipped checks
   - Severity breakdown visualization
   - Filterable and searchable check list

### Features

- **📊 Dashboard View**: Clean overview of all check results
- **🔍 Search**: Find checks by name or ID
- **🎚️ Filters**: Filter by status (passed/failed/skipped) and severity (critical/high/medium/low)
- **📋 Expandable Details**: Click any check to see full details, remediation hints, and technical details
- **💾 Export**: Export filtered results as JSON
- **⌨️ Keyboard Shortcuts**:
  - `Ctrl+O` - Open JSON file
  - `Ctrl+F` - Focus search box
  - `Esc` - Close modal / Clear search
  - `?` - Show keyboard shortcuts

### Viewer Files

The viewer is located in the `viewer/` directory:

```
viewer/
├── index.html    # Main application
├── style.css     # Dark theme styling
└── app.js        # Application logic (vanilla JS)
```

No build step or server required - works offline with the `file://` protocol.

## Check Categories

The tool covers the following CIS benchmark categories:

### Authentication (auth_*)
- **Password Complexity**: Checks PAM pwquality/cracklib configuration
- **Account Lockout**: Verifies failed login attempt policies
- **Password Expiration**: Checks password aging settings
- **Empty Password Accounts**: Detects accounts without passwords
- **Root SSH Access**: Verifies root login restrictions via SSH

### Logging & Auditing (logging_*)
- **Rsyslog Service**: Checks if rsyslog is installed and running
- **Auditd Service**: Verifies audit daemon status
- **Log File Permissions**: Checks secure permissions on log files
- **Remote Logging**: Validates remote log forwarding configuration
- **Audit Rules**: Checks for configured audit rules

### Network Security (network_*)
- **FirewallD**: Verifies firewalld is installed, running, and enabled
- **Default Zone**: Checks default firewall zone configuration
- **IPv6 Configuration**: Reports IPv6 status (informational)
- **TCP Wrappers**: Validates hosts.allow/deny configuration
- **Network Services**: Detects suspicious or unnecessary services

### Filesystem & Permissions (fs_*)
- **/tmp Mount Options**: Checks noexec, nosuid, nodev options
- **/var/tmp Permissions**: Validates sticky bit and permissions
- **World-Writable Files**: Finds world-writable files outside temp directories
- **SUID/SGID Audit**: Audits SUID/SGID files against whitelist
- **Home Directory Permissions**: Checks home directory security (including /root)

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0 | Success | All checks passed |
| 1 | Error | An error occurred during execution |
| 2 | Warnings | Some checks failed (review output for details) |

## JSON Output Structure

The tool produces structured JSON output with the following schema:

```json
{
  "metadata": {
    "schema_version": "1.1",
    "timestamp": "2024-01-15T10:30:00+00:00",
    "hostname": "fedora-server",
    "fedora_version": "43",
    "platform_profile": "fedora-43",
    "distribution": "fedora",
    "distribution_version": "43",
    "distribution_name": "Fedora Linux 43",
    "package_manager": "dnf",
    "service_manager": "systemd",
    "environment": "server",
    "privileged": true
  },
  "summary": {
    "total_checks": 20,
    "passed": 15,
    "failed": 3,
    "skipped": 2,
    "by_severity": {
      "CRITICAL": {"total": 2, "passed": 2, "failed": 0},
      "HIGH": {"total": 5, "passed": 4, "failed": 1},
      "MEDIUM": {"total": 8, "passed": 6, "failed": 2},
      "LOW": {"total": 5, "passed": 3, "failed": 0}
    }
  },
  "checks": [
    {
      "id": "auth_password_complexity",
      "name": "Password Complexity Requirements",
      "passed": true,
      "skipped": false,
      "severity": "HIGH",
      "message": "Password complexity is properly configured",
      "remediation": "",
      "details": {...}
    }
  ]
}
```

## Extending the Tool

### Adding a New Check

1. Create a new Python file in `src/checks/` with a descriptive name:
```bash
touch src/checks/my_custom_check.py
```

2. Implement the check by subclassing `BaseCheck`:

```python
"""
CIS Audit Check: My Custom Check

Description of what this check does.
"""

from src.core.check import BaseCheck, CheckResult, Severity


class MyCustomCheck(BaseCheck):
    """Check for my custom security requirement."""
    
    # Required metadata
    id = "category_check_name"  # lowercase with underscores
    name = "Human-Readable Check Name"
    description = "Detailed description of what this check does"
    severity = Severity.MEDIUM  # CRITICAL, HIGH, MEDIUM, or LOW
    requires_root = False  # Set True if check needs root privileges
    
    def run(self) -> CheckResult:
        """Execute the check.
        
        Returns:
            CheckResult with the outcome of the check
        """
        # Perform your check logic here
        check_passed = self._perform_check()
        
        if check_passed:
            return CheckResult.passed_result(
                check_id=self.id,
                check_name=self.name,
                message="Check passed - everything is configured correctly",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"additional": "information"}
            )
        else:
            return CheckResult.failed_result(
                check_id=self.id,
                check_name=self.name,
                message="Check failed - issue found",
                remediation="Instructions on how to fix the issue",
                severity=self.severity,
                requires_root=self.requires_root,
                details={"found": "problem details"}
            )
    
    def _perform_check(self) -> bool:
        """Internal check logic."""
        # Implement your check logic
        return True
```

3. The check will be automatically discovered on the next run - no registration needed!

### Check ID Naming Convention

- Use lowercase letters and underscores only
- Format: `category_check_name`
- Examples:
  - `auth_password_complexity`
  - `network_firewalld`
  - `fs_tmp_mount`

### Severity Levels

- **CRITICAL**: Immediate security risk requiring urgent attention
- **HIGH**: Significant security issue that should be addressed
- **MEDIUM**: Security recommendation worth implementing
- **LOW**: Informational finding, minor concern

### Check Result Factory Methods

Use these convenience methods to create results:

```python
# For passing checks
return CheckResult.passed_result(
    check_id=self.id,
    check_name=self.name,
    message="Success message",
    severity=self.severity,
    details={"extra": "info"}
)

# For failing checks
return CheckResult.failed_result(
    check_id=self.id,
    check_name=self.name,
    message="Failure message",
    remediation="How to fix this",
    severity=self.severity,
    details={"found": "problem"}
)

# For skipped checks (automatic when requires_root=True and no sudo)
return CheckResult.skipped_result(
    check_id=self.id,
    check_name=self.name,
    message="Why this was skipped",
    severity=self.severity
)
```

## Project Structure

```
cis-audit-f43/
├── catoscan.py              # Main executable entry point
├── README.md                 # This file
├── ROADMAP.md                # Project roadmap and status
├── viewer/                   # Web-based results viewer
│   ├── index.html            # Viewer HTML application
│   ├── style.css             # Dark theme styles
│   └── app.js                # Viewer JavaScript logic
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
│       ├── json_formatter.py # JSON output formatting
│       └── progress.py       # CLI progress bar
└── tests/
    ├── test_detector.py      # Environment detection tests
    ├── test_check_framework.py  # Check framework tests
    ├── test_json_formatter.py   # JSON formatter tests
    └── test_integration.py   # Integration tests
```

## Testing

Run the test suite with pytest:

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_integration.py -v

# Run with coverage
python3 -m pytest tests/ --cov=src --cov-report=html
```

## Contributing

Contributions are welcome! When adding new checks:

1. Follow the existing code style and naming conventions
2. Include comprehensive docstrings
3. Add unit tests for new functionality
4. Update this README with new check documentation

## License

[Your License Here]

## Security Notes

- This tool is **read-only** and makes no changes to your system
- Some checks require root privileges to read system files
- Fedora 43 is the compatibility baseline; Ubuntu 24.04 profile support is in pilot rollout
- Output keeps `metadata.fedora_version` for backward compatibility with existing consumers
- Always review remediation suggestions before applying them to your system

## Support

For issues, questions, or contributions, please refer to the project repository.
