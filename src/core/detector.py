"""
CIS Audit Tool for Fedora 43 - Detection Engine

This module provides environment detection capabilities to determine
whether the system is running as a desktop or server environment.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional
import os

from .platform import PlatformContext, get_platform_context


class EnvironmentType(Enum):
    """Enumeration of possible environment types."""
    DESKTOP = "desktop"
    SERVER = "server"
    UNKNOWN = "unknown"


@dataclass
class DetectionResult:
    """Result of environment detection with confidence score.
    
    Attributes:
        environment: The detected environment type
        confidence: Score between 0.0 and 1.0 indicating confidence
        signals: Dictionary of detected signals and their weights
        override_used: Whether CLI override was applied
    """
    environment: EnvironmentType
    confidence: float
    signals: dict[str, float]
    override_used: bool = False


class EnvironmentDetector:
    """Detects whether the system is a desktop or server environment.
    
    Uses a weighted scoring algorithm based on multiple signals:
    - Desktop signals: display managers, graphical sessions, desktop packages
    - Server signals: SSH, web servers, databases, container runtimes
    
    The detector can be overridden via CLI flags to force a specific environment.
    """
    
    # Desktop signal weights
    DESKTOP_SIGNALS: dict[str, float] = {
        # Display managers (strong signal)
        "gdm": 0.9,
        "sddm": 0.9,
        "lightdm": 0.9,
        "xdm": 0.8,
        "slim": 0.8,
        # Desktop packages (strong signal)
        "gnome-desktop": 0.85,
        "kde-desktop": 0.85,
        "xfce4-desktop": 0.85,
        "cinnamon-desktop": 0.85,
        "mate-desktop": 0.85,
        "lxde-desktop": 0.85,
        "lxqt-desktop": 0.85,
        # Session indicators (strong signal)
        "x11_session": 0.9,
        "wayland_session": 0.9,
        # Systemd target (strong signal)
        "graphical_target": 0.8,
    }
    
    # Server signal weights
    SERVER_SIGNALS: dict[str, float] = {
        # SSH daemon (moderate signal - can be on desktop too)
        "sshd": 0.5,
        # Web servers (strong signal)
        "nginx": 0.75,
        "httpd": 0.75,
        "apache2": 0.75,
        "lighttpd": 0.7,
        # Databases (strong signal)
        "postgresql": 0.8,
        "mysql": 0.8,
        "mariadb": 0.8,
        "mongodb": 0.8,
        "redis": 0.75,
        "memcached": 0.7,
        # Container runtimes (strong signal)
        "docker": 0.75,
        "podman": 0.75,
        "containerd": 0.75,
        "cri-o": 0.75,
        # Systemd target (strong signal)
        "multi_user_target": 0.7,
        # Mail servers (strong signal)
        "postfix": 0.7,
        "dovecot": 0.7,
        "exim": 0.7,
        # Monitoring/logging servers
        "prometheus": 0.8,
        "grafana-server": 0.8,
        "elasticsearch": 0.8,
    }
    
    # Thresholds for classification
    CONFIDENCE_THRESHOLD: float = 0.3  # Minimum score to classify
    HIGH_CONFIDENCE: float = 0.7  # High confidence threshold
    
    def __init__(
        self,
        force_desktop: bool = False,
        force_server: bool = False,
        platform_context: Optional[PlatformContext] = None,
    ) -> None:
        """Initialize the detector.
        
        Args:
            force_desktop: If True, always return DESKTOP environment
            force_server: If True, always return SERVER environment
            platform_context: Optional platform context with distro adapters
            
        Raises:
            ValueError: If both force_desktop and force_server are True
        """
        if force_desktop and force_server:
            raise ValueError(
                "Cannot force both desktop and server environments"
            )
        self._force_desktop = force_desktop
        self._force_server = force_server
        self._platform_context = platform_context or get_platform_context()
    
    def detect(self) -> DetectionResult:
        """Detect the environment type.
        
        Returns:
            DetectionResult with environment type, confidence, and signals
        """
        # Handle CLI overrides first
        if self._force_desktop:
            return DetectionResult(
                environment=EnvironmentType.DESKTOP,
                confidence=1.0,
                signals={"force_desktop_flag": 1.0},
                override_used=True
            )
        
        if self._force_server:
            return DetectionResult(
                environment=EnvironmentType.SERVER,
                confidence=1.0,
                signals={"force_server_flag": 1.0},
                override_used=True
            )
        
        # Collect all signals
        desktop_score, desktop_signals = self._detect_desktop_signals()
        server_score, server_signals = self._detect_server_signals()
        
        # Combine signals
        all_signals = {**desktop_signals, **server_signals}
        
        # Calculate confidence and determine environment
        total_score = desktop_score + server_score
        
        if total_score < self.CONFIDENCE_THRESHOLD:
            # Not enough signals to make a determination
            return DetectionResult(
                environment=EnvironmentType.UNKNOWN,
                confidence=0.0,
                signals=all_signals
            )
        
        # Calculate relative confidence
        desktop_ratio = desktop_score / total_score if total_score > 0 else 0
        server_ratio = server_score / total_score if total_score > 0 else 0
        
        # Determine environment based on ratio
        if desktop_ratio > server_ratio:
            confidence = desktop_ratio
            environment = EnvironmentType.DESKTOP
        elif server_ratio > desktop_ratio:
            confidence = server_ratio
            environment = EnvironmentType.SERVER
        else:
            # Exactly equal - unknown
            confidence = 0.5
            environment = EnvironmentType.UNKNOWN
        
        return DetectionResult(
            environment=environment,
            confidence=confidence,
            signals=all_signals
        )
    
    def _detect_desktop_signals(self) -> tuple[float, dict[str, float]]:
        """Detect desktop-specific signals.
        
        Returns:
            Tuple of (total_score, detected_signals)
        """
        score = 0.0
        signals: dict[str, float] = {}
        
        # Check for display managers
        display_managers = ["gdm", "sddm", "lightdm", "xdm", "slim"]
        for dm in display_managers:
            if self._is_service_active(dm):
                weight = self.DESKTOP_SIGNALS.get(dm, 0.5)
                score += weight
                signals[dm] = weight
        
        # Check for desktop packages (using rpm on Fedora)
        desktop_packages = [
            "gnome-desktop", "kde-desktop", "xfce4-desktop",
            "cinnamon-desktop", "mate-desktop", "lxde-desktop", "lxqt-desktop"
        ]
        for pkg in desktop_packages:
            if self._is_package_installed(pkg):
                weight = self.DESKTOP_SIGNALS.get(pkg, 0.5)
                score += weight
                signals[pkg] = weight
        
        # Check for X11/Wayland sessions
        if self._has_x11_session():
            weight = self.DESKTOP_SIGNALS["x11_session"]
            score += weight
            signals["x11_session"] = weight
        
        if self._has_wayland_session():
            weight = self.DESKTOP_SIGNALS["wayland_session"]
            score += weight
            signals["wayland_session"] = weight
        
        # Check systemd target
        if self._is_graphical_target():
            weight = self.DESKTOP_SIGNALS["graphical_target"]
            score += weight
            signals["graphical_target"] = weight
        
        return score, signals
    
    def _detect_server_signals(self) -> tuple[float, dict[str, float]]:
        """Detect server-specific signals.
        
        Returns:
            Tuple of (total_score, detected_signals)
        """
        score = 0.0
        signals: dict[str, float] = {}
        
        # Check for SSH daemon
        if self._is_service_active("sshd"):
            weight = self.SERVER_SIGNALS["sshd"]
            score += weight
            signals["sshd"] = weight
        
        # Check for web servers
        web_servers = ["nginx", "httpd", "apache2", "lighttpd"]
        for ws in web_servers:
            if self._is_service_active(ws):
                weight = self.SERVER_SIGNALS.get(ws, 0.5)
                score += weight
                signals[ws] = weight
        
        # Check for databases
        databases = ["postgresql", "mysql", "mariadb", "mongodb", "redis"]
        for db in databases:
            if self._is_service_active(db):
                weight = self.SERVER_SIGNALS.get(db, 0.5)
                score += weight
                signals[db] = weight
        
        # Check for container runtimes
        containers = ["docker", "podman", "containerd", "cri-o"]
        for container in containers:
            if self._is_service_active(container):
                weight = self.SERVER_SIGNALS.get(container, 0.5)
                score += weight
                signals[container] = weight
        
        # Check for mail servers
        mail_servers = ["postfix", "dovecot", "exim"]
        for mail in mail_servers:
            if self._is_service_active(mail):
                weight = self.SERVER_SIGNALS.get(mail, 0.5)
                score += weight
                signals[mail] = weight
        
        # Check systemd target
        if self._is_multi_user_target():
            weight = self.SERVER_SIGNALS["multi_user_target"]
            score += weight
            signals["multi_user_target"] = weight
        
        return score, signals
    
    def _is_service_active(self, service_name: str) -> bool:
        """Check if a service is active using platform adapters.
        
        Args:
            service_name: Name of the service (without .service suffix)
            
        Returns:
            True if service is active, False otherwise
        """
        active, _ = self._platform_context.check_service_active(f"{service_name}.service")
        return active
    
    def _is_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed using platform adapters.
        
        Args:
            package_name: Name of the package to check
            
        Returns:
            True if package is installed, False otherwise
        """
        installed, _ = self._platform_context.check_package_installed(package_name)
        return installed
    
    def _has_x11_session(self) -> bool:
        """Check if X11 session is available.
        
        Returns:
            True if X11 display is detected, False otherwise
        """
        # Check DISPLAY environment variable
        if os.environ.get("DISPLAY"):
            return True
        
        # Check for X11 socket
        if os.path.exists("/tmp/.X11-unix"):
            try:
                return len(os.listdir("/tmp/.X11-unix")) > 0
            except (PermissionError, OSError):
                pass
        
        return False
    
    def _has_wayland_session(self) -> bool:
        """Check if Wayland session is available.
        
        Returns:
            True if Wayland display is detected, False otherwise
        """
        # Check WAYLAND_DISPLAY environment variable
        if os.environ.get("WAYLAND_DISPLAY"):
            return True
        
        # Check for Wayland socket in runtime dir
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        wayland_socket = os.path.join(runtime_dir, "wayland-0")
        if os.path.exists(wayland_socket):
            return True
        
        return False
    
    def _is_graphical_target(self) -> bool:
        """Check if graphical.target is default or active.
        
        Returns:
            True if graphical target is active/default, False otherwise
        """
        default_target = self._platform_context.get_default_target()
        if "graphical.target" in default_target:
            return True

        return self._platform_context.is_target_active("graphical.target")
    
    def _is_multi_user_target(self) -> bool:
        """Check if multi-user.target is default or active.
        
        Returns:
            True if multi-user target is active/default, False otherwise
        """
        default_target = self._platform_context.get_default_target()
        if "multi-user.target" in default_target:
            return True

        return self._platform_context.is_target_active("multi-user.target")


def detect_environment(
    force_desktop: bool = False,
    force_server: bool = False,
    platform_context: Optional[PlatformContext] = None,
) -> DetectionResult:
    """Convenience function to detect environment.
    
    Args:
        force_desktop: Force desktop environment detection
        force_server: Force server environment detection
        platform_context: Optional platform context with distro adapters
        
    Returns:
        DetectionResult with environment information
    """
    detector = EnvironmentDetector(
        force_desktop=force_desktop,
        force_server=force_server,
        platform_context=platform_context,
    )
    return detector.detect()
