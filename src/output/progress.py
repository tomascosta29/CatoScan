"""
CIS Audit Tool for Fedora 43 - Progress Bar

This module provides progress bar functionality for the CLI,
with support for both rich terminal displays and fallback to
simple text output for non-TTY environments.
"""

import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional, TextIO


@dataclass
class ProgressState:
    """State of the current progress operation."""
    current: int = 0
    total: int = 0
    check_name: str = ""
    check_id: str = ""
    status: str = "pending"  # pending, running, passed, failed, skipped
    start_time: float = 0.0


class ProgressBar:
    """Progress bar for CIS check execution.
    
    Provides a visual progress indicator during audit execution with:
    - Percentage complete
    - Elapsed time
    - Estimated time remaining
    - Color-coded status indicators
    - Graceful fallback for non-TTY output
    
    Example:
        with ProgressBar(total=20, verbose=True) as pb:
            for check in checks:
                pb.update(check_name=check.name, status="running")
                result = check.execute()
                pb.update(status="passed" if result.passed else "failed")
                pb.increment()
    """
    
    # Status symbols
    SYMBOLS = {
        "pending": "○",
        "running": "◐",
        "passed": "✓",
        "failed": "✗",
        "skipped": "⊘",
    }
    
    # ANSI color codes
    COLORS = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "gray": "\033[90m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }
    
    def __init__(
        self,
        total: int,
        verbose: bool = False,
        file: Optional[TextIO] = None,
        disable: bool = False,
        width: int = 40
    ) -> None:
        """Initialize the progress bar.
        
        Args:
            total: Total number of items to process
            verbose: If True, show detailed check information
            file: Output stream (defaults to sys.stderr)
            disable: If True, disable the progress bar entirely
            width: Width of the progress bar in characters
        """
        self.total = total
        self.verbose = verbose
        self.file = file or sys.stderr
        self.width = width
        self.state = ProgressState(total=total, start_time=time.time())
        
        # Determine if we can use fancy output
        self._is_tty = hasattr(self.file, 'isatty') and self.file.isatty()
        self._use_colors = self._is_tty and not disable
        self._disabled = disable or total == 0
        
        # For callback integration
        self._pre_check_callbacks: list[Callable[[str, str], None]] = []
        self._post_check_callbacks: list[Callable[[str, str, bool], None]] = []
    
    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self._use_colors:
            return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"
        return text
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds as MM:SS."""
        mins, secs = divmod(int(seconds), 60)
        return f"{mins:02d}:{secs:02d}"
    
    def _format_eta(self, elapsed: float, current: int, total: int) -> str:
        """Calculate and format estimated time remaining."""
        if current == 0:
            return "--:--"
        rate = elapsed / current
        remaining = rate * (total - current)
        return self._format_time(remaining)
    
    def _render_bar(self) -> str:
        """Render the progress bar."""
        if not self._is_tty:
            return self._render_text()
        
        elapsed = time.time() - self.state.start_time
        percent = (self.state.current / self.state.total * 100) if self.state.total > 0 else 0
        
        # Build progress bar
        filled = int(self.width * self.state.current / self.state.total) if self.state.total > 0 else 0
        bar_fill = "█" * filled + "░" * (self.width - filled)
        
        # Color based on status
        status_color = "blue"
        if self.state.status == "passed":
            status_color = "green"
        elif self.state.status == "failed":
            status_color = "red"
        elif self.state.status == "skipped":
            status_color = "yellow"
        elif self.state.status == "running":
            status_color = "cyan"
        
        symbol = self.SYMBOLS.get(self.state.status, "○")
        colored_symbol = self._color(symbol, status_color)
        colored_bar = self._color(bar_fill, "cyan" if self.state.status == "running" else "blue")
        
        # Build the line
        parts = [
            f"\r",  # Return to start of line
            f"{colored_symbol} ",
            f"Check {self.state.current}/{self.state.total} ",
            f"[{colored_bar}] ",
            f"{percent:5.1f}% ",
            f"| {self._format_time(elapsed)} < {self._format_eta(elapsed, self.state.current, self.state.total)}",
        ]
        
        if self.verbose and self.state.check_name:
            parts.append(f" | {self.state.check_name[:30]}")
        
        return "".join(parts)
    
    def _render_text(self) -> str:
        """Render simple text output for non-TTY."""
        symbol = self.SYMBOLS.get(self.state.status, "○")
        status_str = f"[{symbol}] Check {self.state.current}/{self.state.total}"
        
        if self.state.check_name:
            status_str += f": {self.state.check_name}"
        
        if self.state.status in ("passed", "failed", "skipped"):
            status_str += f" - {self.state.status.upper()}"
        
        return status_str + "\n"
    
    def update(
        self,
        current: Optional[int] = None,
        check_name: Optional[str] = None,
        check_id: Optional[str] = None,
        status: Optional[str] = None
    ) -> None:
        """Update the progress bar state.
        
        Args:
            current: Current item number (1-based)
            check_name: Name of the current check
            check_id: ID of the current check
            status: Current status (pending, running, passed, failed, skipped)
        """
        if self._disabled:
            return
        
        if current is not None:
            self.state.current = current
        if check_name is not None:
            self.state.check_name = check_name
        if check_id is not None:
            self.state.check_id = check_id
        if status is not None:
            self.state.status = status
        
        self._draw()
    
    def increment(self, status: str = "pending") -> None:
        """Increment the progress counter.
        
        Args:
            status: Status for the next item
        """
        if self._disabled:
            return
        
        self.state.current += 1
        self.state.status = status
        self._draw()
    
    def _draw(self) -> None:
        """Draw the current progress state."""
        if self._disabled:
            return
        
        output = self._render_bar()
        self.file.write(output)
        self.file.flush()
    
    def clear(self) -> None:
        """Clear the progress bar from the terminal."""
        if self._disabled or not self._is_tty:
            return
        
        # Clear the line
        self.file.write("\r" + " " * 100 + "\r")
        self.file.flush()
    
    def finish(self, message: Optional[str] = None) -> None:
        """Finish the progress bar and optionally print a summary.
        
        Args:
            message: Optional final message to display
        """
        if self._disabled:
            return
        
        if self._is_tty:
            self.clear()
            if message:
                self.file.write(message + "\n")
        else:
            if message:
                self.file.write(message + "\n")
        
        self.file.flush()
    
    def on_check_start(self, check_id: str, check_name: str) -> None:
        """Callback for when a check starts.
        
        Args:
            check_id: ID of the check starting
            check_name: Name of the check starting
        """
        self.update(
            check_id=check_id,
            check_name=check_name,
            status="running"
        )
        
        for callback in self._pre_check_callbacks:
            callback(check_id, check_name)
    
    def on_check_complete(self, check_id: str, check_name: str, passed: bool, skipped: bool = False) -> None:
        """Callback for when a check completes.
        
        Args:
            check_id: ID of the completed check
            check_name: Name of the completed check
            passed: Whether the check passed
            skipped: Whether the check was skipped
        """
        if skipped:
            status = "skipped"
        elif passed:
            status = "passed"
        else:
            status = "failed"
        
        self.update(status=status)
        
        # Small delay to show the final state
        if self._is_tty:
            time.sleep(0.05)
        
        for callback in self._post_check_callbacks:
            callback(check_id, check_name, passed)
    
    def add_pre_check_callback(self, callback: Callable[[str, str], None]) -> None:
        """Add a callback to be called before each check starts."""
        self._pre_check_callbacks.append(callback)
    
    def add_post_check_callback(self, callback: Callable[[str, str, bool], None]) -> None:
        """Add a callback to be called after each check completes."""
        self._post_check_callbacks.append(callback)
    
    def __enter__(self) -> "ProgressBar":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.finish()


class NullProgressBar:
    """A no-op progress bar for when progress is disabled.
    
    This class provides the same interface as ProgressBar but does nothing,
    allowing code to use progress bars unconditionally.
    """
    
    def __init__(self, *args, **kwargs) -> None:
        pass
    
    def update(self, *args, **kwargs) -> None:
        pass
    
    def increment(self, *args, **kwargs) -> None:
        pass
    
    def clear(self) -> None:
        pass
    
    def finish(self, *args, **kwargs) -> None:
        pass
    
    def on_check_start(self, *args, **kwargs) -> None:
        pass
    
    def on_check_complete(self, *args, **kwargs) -> None:
        pass
    
    def add_pre_check_callback(self, callback: Callable) -> None:
        pass
    
    def add_post_check_callback(self, callback: Callable) -> None:
        pass
    
    def __enter__(self) -> "NullProgressBar":
        return self
    
    def __exit__(self, *args) -> None:
        pass


def create_progress_bar(
    total: int,
    verbose: bool = False,
    disable: bool = False,
    file: Optional[TextIO] = None
) -> ProgressBar:
    """Factory function to create a progress bar.
    
    Args:
        total: Total number of items
        verbose: Enable verbose output
        disable: Disable progress bar entirely
        file: Output stream
        
    Returns:
        ProgressBar instance (or NullProgressBar if disabled)
    """
    if disable:
        return NullProgressBar()
    return ProgressBar(total=total, verbose=verbose, file=file, disable=disable)
