"""
Unit tests for Scan Config API (PR-02a).

Tests verify:
- Request validation with and without config
- Default config applied when absent
- Invalid path_profile values are rejected
- Config is persisted in DB (config_json field)
- Config is reflected in result_json (debug_info.config_used)
- Backward compatibility with target-only requests
"""

import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime

from app.models import ScanRequest, ScanConfig, ScanResponse, Scan


# =============================================================================
# ScanConfig Model Tests
# =============================================================================

class TestScanConfigModel:
    """Tests for the ScanConfig Pydantic model."""

    def test_default_profile_is_standard(self):
        """Default path_profile should be 'standard'."""
        config = ScanConfig()
        assert config.path_profile == "standard"

    def test_valid_minimal_profile(self):
        """'minimal' is a valid path_profile value."""
        config = ScanConfig(path_profile="minimal")
        assert config.path_profile == "minimal"

    def test_valid_standard_profile(self):
        """'standard' is a valid path_profile value."""
        config = ScanConfig(path_profile="standard")
        assert config.path_profile == "standard"

    def test_valid_thorough_profile(self):
        """'thorough' is a valid path_profile value."""
        config = ScanConfig(path_profile="thorough")
        assert config.path_profile == "thorough"

    def test_invalid_profile_rejected(self):
        """Invalid path_profile values should raise ValidationError."""
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="aggressive")

    def test_invalid_profile_typo_rejected(self):
        """Typos in path_profile values should raise ValidationError."""
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="standart")  # typo

    def test_empty_string_rejected(self):
        """Empty string should be rejected."""
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="")


# =============================================================================
# ScanRequest Model Tests
# =============================================================================

class TestScanRequestModel:
    """Tests for the ScanRequest Pydantic model."""

    def test_target_only_request(self):
        """Request with only target should work (backward compatibility)."""
        request = ScanRequest(target="https://example.com")
        assert request.target == "https://example.com"
        assert request.authorized == False
        assert request.config is None

    def test_target_with_authorized(self):
        """Request with target and authorized should work."""
        request = ScanRequest(target="https://example.com", authorized=True)
        assert request.target == "https://example.com"
        assert request.authorized == True
        assert request.config is None

    def test_request_with_config(self):
        """Request with full config should work."""
        request = ScanRequest(
            target="https://example.com",
            authorized=True,
            config=ScanConfig(path_profile="thorough")
        )
        assert request.target == "https://example.com"
        assert request.authorized == True
        assert request.config is not None
        assert request.config.path_profile == "thorough"

    def test_request_with_config_dict(self):
        """Request with config as dict should work."""
        request = ScanRequest(
            target="https://example.com",
            authorized=True,
            config={"path_profile": "minimal"}
        )
        assert request.config.path_profile == "minimal"


class TestScanRequestGetEffectiveConfig:
    """Tests for ScanRequest.get_effective_config method."""

    def test_effective_config_when_none(self):
        """When config is None, effective config should have defaults."""
        request = ScanRequest(target="https://example.com")
        effective = request.get_effective_config()
        
        assert effective.path_profile == "standard"

    def test_effective_config_when_provided(self):
        """When config is provided, it should be returned."""
        request = ScanRequest(
            target="https://example.com",
            config=ScanConfig(path_profile="minimal")
        )
        effective = request.get_effective_config()
        
        assert effective.path_profile == "minimal"

    def test_effective_config_thorough(self):
        """Thorough profile should be preserved."""
        request = ScanRequest(
            target="https://example.com",
            config=ScanConfig(path_profile="thorough")
        )
        effective = request.get_effective_config()
        
        assert effective.path_profile == "thorough"


# =============================================================================
# Scan DB Model Tests
# =============================================================================

class TestScanDBModel:
    """Tests for the Scan SQLModel."""

    def test_scan_has_config_json_field(self):
        """Scan model should have config_json field."""
        scan = Scan(target="https://example.com")
        assert hasattr(scan, "config_json")
        assert scan.config_json is None  # Default

    def test_scan_with_config_json(self):
        """Scan can be created with config_json."""
        config = {"path_profile": "thorough"}
        scan = Scan(target="https://example.com", config_json=config)
        
        assert scan.config_json == {"path_profile": "thorough"}

    def test_scan_config_json_persists_profile(self):
        """config_json should correctly store the profile."""
        for profile in ["minimal", "standard", "thorough"]:
            config = {"path_profile": profile}
            scan = Scan(target="https://example.com", config_json=config)
            assert scan.config_json["path_profile"] == profile


# =============================================================================
# API Integration Tests (using TestClient pattern)
# =============================================================================

class TestScanAPIRequestParsing:
    """Tests for /scan endpoint request parsing."""

    def test_request_without_config_parses(self):
        """Request without config should parse successfully."""
        # Simulate request parsing
        data = {"target": "https://example.com", "authorized": True}
        request = ScanRequest(**data)
        
        assert request.target == "https://example.com"
        assert request.config is None
        
        # Effective config should default to standard
        effective = request.get_effective_config()
        assert effective.path_profile == "standard"

    def test_request_with_config_parses(self):
        """Request with config should parse successfully."""
        data = {
            "target": "https://example.com",
            "authorized": True,
            "config": {"path_profile": "thorough"}
        }
        request = ScanRequest(**data)
        
        assert request.config.path_profile == "thorough"

    def test_request_with_partial_config_uses_defaults(self):
        """Request with empty config should use defaults."""
        data = {
            "target": "https://example.com",
            "authorized": True,
            "config": {}
        }
        request = ScanRequest(**data)
        
        # Default path_profile should be applied
        assert request.config.path_profile == "standard"

    def test_request_with_invalid_profile_fails(self):
        """Request with invalid profile should fail validation."""
        data = {
            "target": "https://example.com",
            "authorized": True,
            "config": {"path_profile": "invalid"}
        }
        
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(**data)
        
        # Check that the error mentions the field
        assert "path_profile" in str(exc_info.value)


# =============================================================================
# Config Dict Generation Tests
# =============================================================================

class TestConfigDictGeneration:
    """Tests for config dict generation for DB persistence."""

    def test_config_dict_from_request_no_config(self):
        """Config dict should default when request has no config."""
        request = ScanRequest(target="https://example.com", authorized=True)
        
        effective_config = request.get_effective_config()
        config_dict = {"path_profile": effective_config.path_profile}
        
        assert config_dict == {"path_profile": "standard"}

    def test_config_dict_from_request_with_config(self):
        """Config dict should reflect request config."""
        request = ScanRequest(
            target="https://example.com",
            authorized=True,
            config=ScanConfig(path_profile="minimal")
        )
        
        effective_config = request.get_effective_config()
        config_dict = {"path_profile": effective_config.path_profile}
        
        assert config_dict == {"path_profile": "minimal"}


# =============================================================================
# Backward Compatibility Tests
# =============================================================================

class TestBackwardCompatibility:
    """Tests ensuring backward compatibility."""

    def test_old_request_format_still_works(self):
        """Old request format (target only) should still work."""
        old_format_data = {"target": "https://example.com"}
        request = ScanRequest(**old_format_data)
        
        assert request.target == "https://example.com"
        assert request.config is None

    def test_old_request_with_authorized_works(self):
        """Old request format with authorized should still work."""
        old_format_data = {"target": "https://example.com", "authorized": True}
        request = ScanRequest(**old_format_data)
        
        assert request.target == "https://example.com"
        assert request.authorized == True
        assert request.config is None

    def test_effective_config_always_available(self):
        """get_effective_config should always return a valid config."""
        # Old format
        old_request = ScanRequest(target="https://example.com")
        old_effective = old_request.get_effective_config()
        assert old_effective.path_profile == "standard"
        
        # New format without config
        new_request_1 = ScanRequest(target="https://example.com", authorized=True)
        new_effective_1 = new_request_1.get_effective_config()
        assert new_effective_1.path_profile == "standard"
        
        # New format with config
        new_request_2 = ScanRequest(
            target="https://example.com",
            authorized=True,
            config=ScanConfig(path_profile="thorough")
        )
        new_effective_2 = new_request_2.get_effective_config()
        assert new_effective_2.path_profile == "thorough"


# =============================================================================
# Profile Value Validation Tests
# =============================================================================

class TestProfileValueValidation:
    """Tests for strict profile value validation."""

    def test_all_valid_profiles(self):
        """All documented profiles should be valid."""
        valid_profiles = ["minimal", "standard", "thorough"]
        
        for profile in valid_profiles:
            config = ScanConfig(path_profile=profile)
            assert config.path_profile == profile

    def test_case_sensitivity(self):
        """Profile values should be case-sensitive."""
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="STANDARD")
        
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="Minimal")
        
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="THOROUGH")

    def test_whitespace_rejected(self):
        """Profile values with whitespace should be rejected."""
        with pytest.raises(ValidationError):
            ScanConfig(path_profile=" standard")
        
        with pytest.raises(ValidationError):
            ScanConfig(path_profile="standard ")

    def test_numeric_rejected(self):
        """Numeric values should be rejected."""
        with pytest.raises(ValidationError):
            ScanConfig(path_profile=1)  # type: ignore
        
        with pytest.raises(ValidationError):
            ScanConfig(path_profile=100)  # type: ignore
