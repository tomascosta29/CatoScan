"""
Unit tests for the environment detection engine.

Tests cover:
- Desktop signal detection
- Server signal detection
- Scoring algorithm
- CLI override functionality
- Edge cases
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.detector import (
    EnvironmentDetector,
    EnvironmentType,
    DetectionResult,
    detect_environment,
)


class TestEnvironmentType(unittest.TestCase):
    """Tests for EnvironmentType enum."""
    
    def test_enum_values(self) -> None:
        """Test that enum values are correct."""
        self.assertEqual(EnvironmentType.DESKTOP.value, "desktop")
        self.assertEqual(EnvironmentType.SERVER.value, "server")
        self.assertEqual(EnvironmentType.UNKNOWN.value, "unknown")


class TestDetectionResult(unittest.TestCase):
    """Tests for DetectionResult dataclass."""
    
    def test_detection_result_creation(self) -> None:
        """Test DetectionResult can be created with all fields."""
        result = DetectionResult(
            environment=EnvironmentType.DESKTOP,
            confidence=0.85,
            signals={"gdm": 0.9, "graphical_target": 0.8},
            override_used=False
        )
        self.assertEqual(result.environment, EnvironmentType.DESKTOP)
        self.assertEqual(result.confidence, 0.85)
        self.assertEqual(result.signals["gdm"], 0.9)
        self.assertFalse(result.override_used)
    
    def test_detection_result_default_override(self) -> None:
        """Test override_used defaults to False."""
        result = DetectionResult(
            environment=EnvironmentType.SERVER,
            confidence=0.75,
            signals={"sshd": 0.5}
        )
        self.assertFalse(result.override_used)


class TestEnvironmentDetectorInitialization(unittest.TestCase):
    """Tests for EnvironmentDetector initialization."""
    
    def test_default_initialization(self) -> None:
        """Test detector initializes with no overrides."""
        detector = EnvironmentDetector()
        self.assertFalse(detector._force_desktop)
        self.assertFalse(detector._force_server)
    
    def test_force_desktop_initialization(self) -> None:
        """Test detector initializes with force_desktop."""
        detector = EnvironmentDetector(force_desktop=True)
        self.assertTrue(detector._force_desktop)
        self.assertFalse(detector._force_server)
    
    def test_force_server_initialization(self) -> None:
        """Test detector initializes with force_server."""
        detector = EnvironmentDetector(force_server=True)
        self.assertFalse(detector._force_desktop)
        self.assertTrue(detector._force_server)
    
    def test_both_forces_raises_error(self) -> None:
        """Test that forcing both desktop and server raises ValueError."""
        with self.assertRaises(ValueError) as context:
            EnvironmentDetector(force_desktop=True, force_server=True)
        self.assertIn("Cannot force both", str(context.exception))


class TestEnvironmentDetectorOverrides(unittest.TestCase):
    """Tests for CLI override functionality."""
    
    def test_force_desktop_override(self) -> None:
        """Test force_desktop returns desktop with 100% confidence."""
        detector = EnvironmentDetector(force_desktop=True)
        result = detector.detect()
        
        self.assertEqual(result.environment, EnvironmentType.DESKTOP)
        self.assertEqual(result.confidence, 1.0)
        self.assertTrue(result.override_used)
        self.assertIn("force_desktop_flag", result.signals)
    
    def test_force_server_override(self) -> None:
        """Test force_server returns server with 100% confidence."""
        detector = EnvironmentDetector(force_server=True)
        result = detector.detect()
        
        self.assertEqual(result.environment, EnvironmentType.SERVER)
        self.assertEqual(result.confidence, 1.0)
        self.assertTrue(result.override_used)
        self.assertIn("force_server_flag", result.signals)


class TestDesktopSignalDetection(unittest.TestCase):
    """Tests for desktop signal detection."""
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_package_installed')
    @patch('core.detector.EnvironmentDetector._has_x11_session')
    @patch('core.detector.EnvironmentDetector._has_wayland_session')
    @patch('core.detector.EnvironmentDetector._is_graphical_target')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_gdm(
        self,
        mock_multi_user: MagicMock,
        mock_graphical: MagicMock,
        mock_wayland: MagicMock,
        mock_x11: MagicMock,
        mock_pkg: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of GDM display manager."""
        mock_service.return_value = True
        mock_pkg.return_value = False
        mock_x11.return_value = False
        mock_wayland.return_value = False
        mock_graphical.return_value = False
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_desktop_signals()
        
        # Should have detected gdm
        self.assertGreater(score, 0)
        self.assertIn("gdm", signals)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_package_installed')
    @patch('core.detector.EnvironmentDetector._has_x11_session')
    @patch('core.detector.EnvironmentDetector._has_wayland_session')
    @patch('core.detector.EnvironmentDetector._is_graphical_target')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_x11_session(
        self,
        mock_multi_user: MagicMock,
        mock_graphical: MagicMock,
        mock_wayland: MagicMock,
        mock_x11: MagicMock,
        mock_pkg: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of X11 session."""
        mock_service.return_value = False
        mock_pkg.return_value = False
        mock_x11.return_value = True
        mock_wayland.return_value = False
        mock_graphical.return_value = False
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_desktop_signals()
        
        self.assertIn("x11_session", signals)
        self.assertEqual(signals["x11_session"], 0.9)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_package_installed')
    @patch('core.detector.EnvironmentDetector._has_x11_session')
    @patch('core.detector.EnvironmentDetector._has_wayland_session')
    @patch('core.detector.EnvironmentDetector._is_graphical_target')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_wayland_session(
        self,
        mock_multi_user: MagicMock,
        mock_graphical: MagicMock,
        mock_wayland: MagicMock,
        mock_x11: MagicMock,
        mock_pkg: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of Wayland session."""
        mock_service.return_value = False
        mock_pkg.return_value = False
        mock_x11.return_value = False
        mock_wayland.return_value = True
        mock_graphical.return_value = False
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_desktop_signals()
        
        self.assertIn("wayland_session", signals)
        self.assertEqual(signals["wayland_session"], 0.9)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_package_installed')
    @patch('core.detector.EnvironmentDetector._has_x11_session')
    @patch('core.detector.EnvironmentDetector._has_wayland_session')
    @patch('core.detector.EnvironmentDetector._is_graphical_target')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_graphical_target(
        self,
        mock_multi_user: MagicMock,
        mock_graphical: MagicMock,
        mock_wayland: MagicMock,
        mock_x11: MagicMock,
        mock_pkg: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of graphical.target."""
        mock_service.return_value = False
        mock_pkg.return_value = False
        mock_x11.return_value = False
        mock_wayland.return_value = False
        mock_graphical.return_value = True
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_desktop_signals()
        
        self.assertIn("graphical_target", signals)
        self.assertEqual(signals["graphical_target"], 0.8)


class TestServerSignalDetection(unittest.TestCase):
    """Tests for server signal detection."""
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_sshd(
        self,
        mock_multi_user: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of SSH daemon."""
        def side_effect(service: str) -> bool:
            return service == "sshd"
        mock_service.side_effect = side_effect
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_server_signals()
        
        self.assertIn("sshd", signals)
        self.assertEqual(signals["sshd"], 0.5)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_nginx(
        self,
        mock_multi_user: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of nginx web server."""
        def side_effect(service: str) -> bool:
            return service == "nginx"
        mock_service.side_effect = side_effect
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_server_signals()
        
        self.assertIn("nginx", signals)
        self.assertEqual(signals["nginx"], 0.75)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_postgresql(
        self,
        mock_multi_user: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of PostgreSQL database."""
        def side_effect(service: str) -> bool:
            return service == "postgresql"
        mock_service.side_effect = side_effect
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_server_signals()
        
        self.assertIn("postgresql", signals)
        self.assertEqual(signals["postgresql"], 0.8)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_docker(
        self,
        mock_multi_user: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of Docker container runtime."""
        def side_effect(service: str) -> bool:
            return service == "docker"
        mock_service.side_effect = side_effect
        mock_multi_user.return_value = False
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_server_signals()
        
        self.assertIn("docker", signals)
        self.assertEqual(signals["docker"], 0.75)
    
    @patch('core.detector.EnvironmentDetector._is_service_active')
    @patch('core.detector.EnvironmentDetector._is_multi_user_target')
    def test_detects_multi_user_target(
        self,
        mock_multi_user: MagicMock,
        mock_service: MagicMock
    ) -> None:
        """Test detection of multi-user.target."""
        mock_service.return_value = False
        mock_multi_user.return_value = True
        
        detector = EnvironmentDetector()
        score, signals = detector._detect_server_signals()
        
        self.assertIn("multi_user_target", signals)
        self.assertEqual(signals["multi_user_target"], 0.7)


class TestScoringAlgorithm(unittest.TestCase):
    """Tests for the scoring algorithm."""
    
    @patch('core.detector.EnvironmentDetector._detect_desktop_signals')
    @patch('core.detector.EnvironmentDetector._detect_server_signals')
    def test_classifies_as_desktop(
        self,
        mock_server: MagicMock,
        mock_desktop: MagicMock
    ) -> None:
        """Test classification as desktop when desktop score is higher."""
        mock_desktop.return_value = (1.5, {"gdm": 0.9, "graphical_target": 0.8})
        mock_server.return_value = (0.5, {"sshd": 0.5})
        
        detector = EnvironmentDetector()
        result = detector.detect()
        
        self.assertEqual(result.environment, EnvironmentType.DESKTOP)
        self.assertGreater(result.confidence, 0.5)
    
    @patch('core.detector.EnvironmentDetector._detect_desktop_signals')
    @patch('core.detector.EnvironmentDetector._detect_server_signals')
    def test_classifies_as_server(
        self,
        mock_server: MagicMock,
        mock_desktop: MagicMock
    ) -> None:
        """Test classification as server when server score is higher."""
        mock_desktop.return_value = (0.5, {"x11_session": 0.5})
        mock_server.return_value = (1.6, {"nginx": 0.75, "postgresql": 0.8, "sshd": 0.5})
        
        detector = EnvironmentDetector()
        result = detector.detect()
        
        self.assertEqual(result.environment, EnvironmentType.SERVER)
        self.assertGreater(result.confidence, 0.5)
    
    @patch('core.detector.EnvironmentDetector._detect_desktop_signals')
    @patch('core.detector.EnvironmentDetector._detect_server_signals')
    def test_classifies_as_unknown_low_signals(
        self,
        mock_server: MagicMock,
        mock_desktop: MagicMock
    ) -> None:
        """Test classification as unknown when total score is below threshold."""
        mock_desktop.return_value = (0.1, {"x11_session": 0.1})
        mock_server.return_value = (0.1, {"sshd": 0.1})
        
        detector = EnvironmentDetector()
        result = detector.detect()
        
        self.assertEqual(result.environment, EnvironmentType.UNKNOWN)
        self.assertEqual(result.confidence, 0.0)
    
    @patch('core.detector.EnvironmentDetector._detect_desktop_signals')
    @patch('core.detector.EnvironmentDetector._detect_server_signals')
    def test_classifies_as_unknown_equal_scores(
        self,
        mock_server: MagicMock,
        mock_desktop: MagicMock
    ) -> None:
        """Test classification as unknown when scores are equal."""
        mock_desktop.return_value = (0.5, {"gdm": 0.5})
        mock_server.return_value = (0.5, {"sshd": 0.5})
        
        detector = EnvironmentDetector()
        result = detector.detect()
        
        self.assertEqual(result.environment, EnvironmentType.UNKNOWN)
        self.assertEqual(result.confidence, 0.5)
    
    @patch('core.detector.EnvironmentDetector._detect_desktop_signals')
    @patch('core.detector.EnvironmentDetector._detect_server_signals')
    def test_confidence_calculation(
        self,
        mock_server: MagicMock,
        mock_desktop: MagicMock
    ) -> None:
        """Test that confidence is calculated as the ratio of winning score."""
        mock_desktop.return_value = (0.9, {"gdm": 0.9})
        mock_server.return_value = (0.3, {"sshd": 0.3})
        
        detector = EnvironmentDetector()
        result = detector.detect()
        
        # Confidence should be desktop_ratio = 0.9 / 1.2 = 0.75
        self.assertAlmostEqual(result.confidence, 0.75, places=2)


class TestConvenienceFunction(unittest.TestCase):
    """Tests for the detect_environment convenience function."""
    
    @patch('core.detector.EnvironmentDetector.detect')
    def test_detect_environment_calls_detector(self, mock_detect: MagicMock) -> None:
        """Test that detect_environment creates and uses EnvironmentDetector."""
        mock_detect.return_value = DetectionResult(
            environment=EnvironmentType.DESKTOP,
            confidence=0.9,
            signals={"gdm": 0.9}
        )
        
        result = detect_environment()
        
        mock_detect.assert_called_once()
        self.assertEqual(result.environment, EnvironmentType.DESKTOP)
    
    def test_detect_environment_with_overrides(self) -> None:
        """Test detect_environment with force flags."""
        result = detect_environment(force_desktop=True)
        self.assertEqual(result.environment, EnvironmentType.DESKTOP)
        self.assertTrue(result.override_used)
        
        result = detect_environment(force_server=True)
        self.assertEqual(result.environment, EnvironmentType.SERVER)
        self.assertTrue(result.override_used)


class TestHelperMethods(unittest.TestCase):
    """Tests for internal helper methods."""
    
    @patch('subprocess.run')
    def test_is_service_active_true(self, mock_run: MagicMock) -> None:
        """Test _is_service_active returns True when service is active."""
        mock_run.return_value = MagicMock(returncode=0, stdout="active\n")
        
        detector = EnvironmentDetector()
        result = detector._is_service_active("sshd")
        
        self.assertTrue(result)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_is_service_active_false(self, mock_run: MagicMock) -> None:
        """Test _is_service_active returns False when service is inactive."""
        mock_run.return_value = MagicMock(returncode=3, stdout="inactive\n")
        
        detector = EnvironmentDetector()
        result = detector._is_service_active("sshd")
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_is_service_active_timeout(self, mock_run: MagicMock) -> None:
        """Test _is_service_active handles timeout gracefully."""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired("cmd", 5)
        
        detector = EnvironmentDetector()
        result = detector._is_service_active("sshd")
        
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_is_package_installed_true(self, mock_run: MagicMock) -> None:
        """Test _is_package_installed returns True when package exists."""
        mock_run.return_value = MagicMock(returncode=0)
        
        detector = EnvironmentDetector()
        result = detector._is_package_installed("gnome-desktop")
        
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_is_package_installed_false(self, mock_run: MagicMock) -> None:
        """Test _is_package_installed returns False when package doesn't exist."""
        mock_run.return_value = MagicMock(returncode=1)
        
        detector = EnvironmentDetector()
        result = detector._is_package_installed("nonexistent")
        
        self.assertFalse(result)
    
    @patch.dict(os.environ, {"DISPLAY": ":0"})
    def test_has_x11_session_from_env(self) -> None:
        """Test X11 detection from DISPLAY environment variable."""
        detector = EnvironmentDetector()
        self.assertTrue(detector._has_x11_session())
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('os.path.exists')
    @patch('os.listdir')
    def test_has_x11_session_from_socket(
        self,
        mock_listdir: MagicMock,
        mock_exists: MagicMock
    ) -> None:
        """Test X11 detection from X11 socket directory."""
        mock_exists.return_value = True
        mock_listdir.return_value = ["X0"]
        
        detector = EnvironmentDetector()
        self.assertTrue(detector._has_x11_session())
    
    @patch.dict(os.environ, {"WAYLAND_DISPLAY": "wayland-0"})
    def test_has_wayland_session_from_env(self) -> None:
        """Test Wayland detection from WAYLAND_DISPLAY environment variable."""
        detector = EnvironmentDetector()
        self.assertTrue(detector._has_wayland_session())
    
    @patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"})
    @patch('os.path.exists')
    def test_has_wayland_session_from_socket(
        self,
        mock_exists: MagicMock
    ) -> None:
        """Test Wayland detection from socket file."""
        mock_exists.return_value = True
        
        detector = EnvironmentDetector()
        self.assertTrue(detector._has_wayland_session())


if __name__ == "__main__":
    unittest.main()
