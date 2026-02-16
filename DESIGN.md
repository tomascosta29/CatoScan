# CatoScan - Design Document

## Architecture Overview

The CIS Audit Tool is a modular, read-only security auditing framework designed to assess Linux systems against CIS (Center for Internet Security) benchmarks. The architecture follows a layered design with clear separation of concerns.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI Layer                                       │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Argument    │  │ Privilege    │  │ Environment  │  │ Audit           │   │
│  │ Parsing     │  │ Checker      │  │ Detector     │  │ Orchestrator    │   │
│  └─────────────┘  └──────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Check Framework                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ BaseCheck   │  │ CheckResult  │  │ Check        │  │ Auto-Discovery │   │
│  │ (Abstract)  │  │ (Dataclass)  │  │ Registry     │  │ Engine          │   │
│  └─────────────┘  └──────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Check Implementations                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ auth_*      │  │ logging_*    │  │ network_*    │  │ fs_*            │   │
│  │ (5 checks)  │  │ (5 checks)   │  │ (5 checks)   │  │ (5 checks)      │   │
│  └─────────────┘  └──────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Output Formatters                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ JSON Formatter (extensible: Markdown, HTML, XML, etc.)                │ │
│  │ - Metadata, Summary, Check Details                                    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. Detection Engine (`src/core/detector.py`)

The Detection Engine determines whether the target system is running as a **desktop** or **server** environment.

#### How Desktop/Server Detection Works

The detector uses a **weighted scoring algorithm** based on multiple signals:

**Desktop Signals (High Weight):**
- Display managers: GDM (0.9), SDDM (0.9), LightDM (0.9)
- Desktop packages: GNOME, KDE, XFCE (0.85 each)
- Graphical sessions: X11 (0.9), Wayland (0.9)
- Systemd target: graphical.target (0.8)

**Server Signals (Moderate to High Weight):**
- SSH daemon: sshd (0.5 - moderate, as desktops may also have SSH)
- Web servers: nginx, httpd (0.75 each)
- Databases: PostgreSQL, MySQL, MongoDB (0.8 each)
- Container runtimes: Docker, Podman (0.75 each)
- Systemd target: multi-user.target (0.7)

**Scoring Algorithm:**
```python
# 1. Collect all signals
desktop_score, desktop_signals = self._detect_desktop_signals()
server_score, server_signals = self._detect_server_signals()

# 2. Calculate relative confidence
total_score = desktop_score + server_score
desktop_ratio = desktop_score / total_score
server_ratio = server_score / total_score

# 3. Classify based on ratio
if desktop_ratio > server_ratio:
    environment = DESKTOP
    confidence = desktop_ratio
elif server_ratio > desktop_ratio:
    environment = SERVER
    confidence = server_ratio
else:
    environment = UNKNOWN
    confidence = 0.5
```

**CLI Overrides:**
- `--force-desktop`: Forces DESKTOP with 100% confidence
- `--force-server`: Forces SERVER with 100% confidence
- `--profile <id>`: Forces a specific distro profile (for deterministic testing)

### Platform Abstraction (`src/core/platform.py`, `src/platforms/*.json`)

The platform layer provides config-driven distro behavior through profile files.

**Responsibilities:**
- Parse `/etc/os-release` and select a matching profile
- Provide package/service/path adapters for checks
- Render remediation command templates per distro

**Current Profiles:**
- `fedora-43` (baseline compatibility profile)
- `ubuntu-24.04` (pilot profile)

**Fallback Behavior:**
- If no matching profile is found, the loader falls back to `fedora-43`

### 2. Check Framework (`src/core/check.py`, `src/core/registry.py`)

#### BaseCheck Abstract Class

All CIS checks inherit from `BaseCheck` and must implement:

```python
class BaseCheck(ABC):
    # Required metadata (class attributes)
    id: str                    # Unique identifier (e.g., "auth_password_complexity")
    name: str                  # Human-readable name
    description: str           # What the check does
    severity: Severity         # CRITICAL, HIGH, MEDIUM, or LOW
    requires_root: bool        # Whether root privileges are needed
    
    # Required method
    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check and return result."""
        pass
```

**Validation:** The `__init_subclass__` hook validates that all required attributes are defined and that the ID follows the naming convention (lowercase with underscores).

#### CheckResult Dataclass

Immutable result object with factory methods:

```python
@dataclass
class CheckResult:
    check_id: str
    check_name: str
    passed: bool
    skipped: bool = False
    message: str = ""
    remediation: str = ""
    severity: Severity = Severity.MEDIUM
    requires_root: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    
    # Factory methods
    @classmethod
    def passed_result(...) -> "CheckResult": ...
    
    @classmethod
    def failed_result(...) -> "CheckResult": ...
    
    @classmethod
    def skipped_result(...) -> "CheckResult": ...
```

#### CheckRegistry

Manages check registration and auto-discovery:

```python
class CheckRegistry:
    def register(self, check_class: Type[BaseCheck]) -> None
    def discover(self, package_path: Optional[str] = None) -> int
    def get_checks(self, requires_root: Optional[bool] = None) -> list[Type[BaseCheck]]
    def run_all(self, privileged: bool = False) -> list[CheckResult]
```

**Auto-Discovery Process:**
1. Scan the `src/checks/` directory for Python modules
2. Import each module using `importlib`
3. Use `inspect.getmembers()` to find `BaseCheck` subclasses
4. Register each discovered check class

### 3. CLI Layer (`src/cli.py`)

#### Argument Parsing

```python
parser.add_argument("--output", "-o", help="Output file path")
parser.add_argument("--verbose", "-v", action="store_true")
parser.add_argument("--force-desktop", action="store_true")
parser.add_argument("--force-server", action="store_true")
parser.add_argument("--no-sudo", action="store_true")
parser.add_argument("--pretty", action="store_true")
```

#### Privilege Handling

The `PrivilegeChecker` class manages privilege requirements:

```python
class PrivilegeChecker:
    def check_privileges(self) -> bool:
        # Check if running as root (uid 0)
        return os.geteuid() == 0
    
    def print_warnings(self) -> None:
        # Warn about skipped checks when not privileged
```

**Behavior:**
- Without `--no-sudo`: Checks for root, warns if missing
- With `--no-sudo`: Skips privilege check, runs unprivileged
- Checks with `requires_root=True` are automatically skipped when unprivileged

### 4. Output Formatters (`src/output/json_formatter.py`)

#### JSON Structure

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

#### Extensibility

New formatters can be added by:
1. Creating a new class in `src/output/`
2. Implementing a `format()` method
3. Adding CLI option to select formatter

## Design Decisions and Rationale

### Why Modular Check System?

**Decision:** Each CIS check is implemented as a separate class inheriting from `BaseCheck`.

**Rationale:**
- **Single Responsibility:** Each check handles one security concern
- **Testability:** Individual checks can be unit tested in isolation
- **Maintainability:** Changes to one check don't affect others
- **Discoverability:** New checks are automatically discovered without registration

### Why Auto-Discovery?

**Decision:** Checks are automatically discovered by scanning the `src/checks/` directory.

**Rationale:**
- **Zero Configuration:** Adding a new check requires no registry updates
- **Reduced Boilerplate:** No need to import and register each check manually
- **Plugin Potential:** Future versions could load checks from external directories

**Trade-offs:**
- Slightly slower startup (scanning filesystem)
- Less explicit than manual registration

### Why Severity Levels?

**Decision:** Four-tier severity system: CRITICAL, HIGH, MEDIUM, LOW.

**Rationale:**
- **Risk Prioritization:** Helps users focus on the most important issues first
- **Compliance Mapping:** Aligns with CIS benchmark severity classifications
- **Reporting:** Enables severity-based filtering and reporting

**Severity Definitions:**
- **CRITICAL:** Immediate security risk requiring urgent attention (e.g., empty root password)
- **HIGH:** Significant security issue (e.g., weak password policy)
- **MEDIUM:** Security recommendation (e.g., audit logging not configured)
- **LOW:** Informational finding (e.g., IPv6 enabled)

## Extension Points

### Adding a New Output Formatter

1. Create a new file in `src/output/`:

```python
# src/output/markdown_formatter.py
from pathlib import Path
from typing import Optional
from ..core.check import CheckResult
from ..core.detector import DetectionResult

class MarkdownFormatter:
    """Formatter for CIS audit results in Markdown format."""
    
    def format(
        self,
        results: list[CheckResult],
        detection_result: Optional[DetectionResult] = None,
        privileged: bool = False
    ) -> str:
        """Format results as Markdown."""
        lines = ["# CIS Audit Report\n"]
        
        # Add metadata section
        lines.append("## Metadata\n")
        # ...
        
        # Add checks
        lines.append("## Checks\n")
        for result in results:
            status = "✅" if result.passed else "❌"
            lines.append(f"### {status} {result.check_name}\n")
            lines.append(f"**Severity:** {result.severity.value}\n")
            lines.append(f"{result.message}\n")
        
        return "\n".join(lines)
```

2. Export from `src/output/__init__.py`:

```python
from .markdown_formatter import MarkdownFormatter

__all__ = ["JSONFormatter", "DateTimeEncoder", "MarkdownFormatter"]
```

3. Add CLI option in `src/cli.py`:

```python
parser.add_argument(
    "--format",
    choices=["json", "markdown"],
    default="json",
    help="Output format"
)
```

### Adding a New Check Category

1. Create a new directory or naming convention:
   - `src/checks/kernel_*.py` for kernel security checks
   - `src/checks/services_*.py` for service-related checks

2. Follow the existing pattern:

```python
# src/checks/kernel_ptr_restrict.py
from src.core.check import BaseCheck, CheckResult, Severity

class KernelPtrRestrictCheck(BaseCheck):
    id = "kernel_ptr_restrict"
    name = "Kernel Pointer Restrictions"
    description = "Checks if kernel pointer restrictions are enabled"
    severity = Severity.HIGH
    requires_root = True
    
    def run(self) -> CheckResult:
        # Check /proc/sys/kernel/kptr_restrict
        # Return appropriate CheckResult
        pass
```

3. The check will be automatically discovered on the next run.

## Security Considerations

### Read-Only Design

**Principle:** The tool never modifies system state.

**Implementation:**
- All file operations use read-only modes (`"r"`)
- No `subprocess` calls with write operations
- No configuration file modifications
- Check results include remediation hints but don't apply them

**Benefits:**
- Safe to run in production environments
- No risk of breaking system configuration
- Can be run repeatedly without side effects

### Privilege Separation

**Principle:** Checks declare their privilege requirements; the framework enforces them.

**Implementation:**
```python
class SensitiveCheck(BaseCheck):
    requires_root = True  # Declares requirement
    
    def run(self) -> CheckResult:
        # This code only runs when privileged
        ...
```

**Framework Enforcement:**
```python
def execute(self) -> CheckResult:
    if self.should_skip():  # requires_root and not privileged
        return CheckResult.skipped_result(...)
    return self.run()
```

**Benefits:**
- Clear audit trail of what requires elevated privileges
- Graceful degradation when run without sudo
- No unexpected permission errors during check execution

### Input Validation

**Check ID Validation:**
```python
def __init_subclass__(cls, **kwargs):
    # Validate id format (lowercase with underscores)
    if not cls.id.replace("_", "").isalnum() or not cls.id.islower():
        raise ValueError(f"Check id '{cls.id}' must be lowercase alphanumeric...")
```

**Result Validation:**
```python
def __post_init__(self):
    if not self.check_id:
        raise ValueError("check_id cannot be empty")
    if self.skipped and self.passed:
        raise ValueError("A skipped check cannot be marked as passed")
```

### Safe Subprocess Usage

All subprocess calls include timeouts and error handling:

```python
def _is_service_active(self, service_name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", f"{service_name}.service"],
            capture_output=True,
            text=True,
            timeout=5  # Prevent hanging
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return False  # Graceful fallback
```

## Performance Considerations

- **Lazy Loading:** Checks are loaded only when needed
- **Parallel Execution:** Future versions could run checks in parallel using `asyncio` or `multiprocessing`
- **Caching:** Detection results could be cached for multiple runs
- **Minimal Dependencies:** Uses only Python standard library for fast startup

## Future Enhancements

1. **Parallel Check Execution:** Run independent checks concurrently
2. **Baseline Comparison:** Compare results against a known-good baseline
3. **Remediation Mode:** Optional mode to automatically fix issues
4. **Web Dashboard:** HTML output with interactive filtering
5. **Policy Customization:** Allow users to define custom check policies
6. **Scheduling Integration:** Built-in cron/systemd timer support
