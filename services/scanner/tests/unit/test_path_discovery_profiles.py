"""
Unit tests for Path Discovery Profiles (PR-02).

Tests verify:
- Each profile resolves the expected number of paths
- STANDARD profile includes all MINIMAL paths
- THOROUGH profile includes all STANDARD paths
- PathDiscoverer does not duplicate paths
- No profile exceeds its intended max path count
- Default profile is STANDARD
- Deterministic path ordering
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.scanner.path_discovery import (
    PathDiscoveryProfile,
    PathDiscoverer,
    get_paths_for_profile,
    PATHS_MINIMAL,
    PATHS_STANDARD_ADDITIONS,
    PATHS_THOROUGH_ADDITIONS,
)


# =============================================================================
# PATH COUNT BOUNDS (from PR-02 requirements)
# =============================================================================

# MINIMAL: ~10-15 paths
MINIMAL_MIN_PATHS = 10
MINIMAL_MAX_PATHS = 15

# STANDARD: ~40-60 paths
STANDARD_MIN_PATHS = 40
STANDARD_MAX_PATHS = 60

# THOROUGH: ~80-120 paths
THOROUGH_MIN_PATHS = 80
THOROUGH_MAX_PATHS = 120


class TestPathDiscoveryProfile:
    """Tests for the PathDiscoveryProfile enum."""

    def test_profile_enum_values(self):
        """Verify the enum has exactly 3 profiles with correct values."""
        assert len(PathDiscoveryProfile) == 3
        assert PathDiscoveryProfile.MINIMAL.value == "minimal"
        assert PathDiscoveryProfile.STANDARD.value == "standard"
        assert PathDiscoveryProfile.THOROUGH.value == "thorough"


class TestGetPathsForProfile:
    """Tests for the get_paths_for_profile function."""

    def test_minimal_profile_path_count(self):
        """MINIMAL profile should have 10-15 paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.MINIMAL)
        assert MINIMAL_MIN_PATHS <= len(paths) <= MINIMAL_MAX_PATHS, \
            f"MINIMAL profile has {len(paths)} paths, expected {MINIMAL_MIN_PATHS}-{MINIMAL_MAX_PATHS}"

    def test_standard_profile_path_count(self):
        """STANDARD profile should have 40-60 paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.STANDARD)
        assert STANDARD_MIN_PATHS <= len(paths) <= STANDARD_MAX_PATHS, \
            f"STANDARD profile has {len(paths)} paths, expected {STANDARD_MIN_PATHS}-{STANDARD_MAX_PATHS}"

    def test_thorough_profile_path_count(self):
        """THOROUGH profile should have 80-120 paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.THOROUGH)
        assert THOROUGH_MIN_PATHS <= len(paths) <= THOROUGH_MAX_PATHS, \
            f"THOROUGH profile has {len(paths)} paths, expected {THOROUGH_MIN_PATHS}-{THOROUGH_MAX_PATHS}"

    def test_minimal_paths_are_subset_of_standard(self):
        """STANDARD profile must include ALL MINIMAL paths."""
        minimal_paths = set(get_paths_for_profile(PathDiscoveryProfile.MINIMAL))
        standard_paths = set(get_paths_for_profile(PathDiscoveryProfile.STANDARD))
        
        missing = minimal_paths - standard_paths
        assert not missing, f"STANDARD is missing MINIMAL paths: {missing}"
        assert minimal_paths.issubset(standard_paths)

    def test_standard_paths_are_subset_of_thorough(self):
        """THOROUGH profile must include ALL STANDARD paths."""
        standard_paths = set(get_paths_for_profile(PathDiscoveryProfile.STANDARD))
        thorough_paths = set(get_paths_for_profile(PathDiscoveryProfile.THOROUGH))
        
        missing = standard_paths - thorough_paths
        assert not missing, f"THOROUGH is missing STANDARD paths: {missing}"
        assert standard_paths.issubset(thorough_paths)

    def test_no_duplicate_paths_minimal(self):
        """MINIMAL profile should have no duplicate paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.MINIMAL)
        assert len(paths) == len(set(paths)), "MINIMAL has duplicate paths"

    def test_no_duplicate_paths_standard(self):
        """STANDARD profile should have no duplicate paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.STANDARD)
        assert len(paths) == len(set(paths)), "STANDARD has duplicate paths"

    def test_no_duplicate_paths_thorough(self):
        """THOROUGH profile should have no duplicate paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.THOROUGH)
        assert len(paths) == len(set(paths)), "THOROUGH has duplicate paths"

    def test_paths_are_deterministic(self):
        """Calling get_paths_for_profile multiple times should return the same order."""
        for profile in PathDiscoveryProfile:
            paths_1 = get_paths_for_profile(profile)
            paths_2 = get_paths_for_profile(profile)
            assert paths_1 == paths_2, f"Non-deterministic paths for {profile.name}"

    def test_all_paths_are_valid_format(self):
        """All paths should start with / and be non-empty strings."""
        for profile in PathDiscoveryProfile:
            paths = get_paths_for_profile(profile)
            for path in paths:
                assert isinstance(path, str), f"Path is not a string: {path}"
                assert len(path) > 0, "Empty path found"
                assert path.startswith("/"), f"Path does not start with /: {path}"


class TestPathSourceLists:
    """Tests for the source path lists themselves."""

    def test_minimal_list_not_empty(self):
        """PATHS_MINIMAL should not be empty."""
        assert len(PATHS_MINIMAL) > 0

    def test_standard_additions_not_empty(self):
        """PATHS_STANDARD_ADDITIONS should not be empty."""
        assert len(PATHS_STANDARD_ADDITIONS) > 0

    def test_thorough_additions_not_empty(self):
        """PATHS_THOROUGH_ADDITIONS should not be empty."""
        assert len(PATHS_THOROUGH_ADDITIONS) > 0

    def test_no_duplicate_in_source_lists(self):
        """Source lists should not have internal duplicates."""
        assert len(PATHS_MINIMAL) == len(set(PATHS_MINIMAL)), "PATHS_MINIMAL has duplicates"
        assert len(PATHS_STANDARD_ADDITIONS) == len(set(PATHS_STANDARD_ADDITIONS)), \
            "PATHS_STANDARD_ADDITIONS has duplicates"
        assert len(PATHS_THOROUGH_ADDITIONS) == len(set(PATHS_THOROUGH_ADDITIONS)), \
            "PATHS_THOROUGH_ADDITIONS has duplicates"


class TestPathDiscovererInit:
    """Tests for PathDiscoverer initialization."""

    def test_default_profile_is_standard(self):
        """Default profile should be STANDARD."""
        mock_client = MagicMock()
        discoverer = PathDiscoverer(http_client=mock_client)
        
        assert discoverer.profile == PathDiscoveryProfile.STANDARD

    def test_custom_profile_minimal(self):
        """Can initialize with MINIMAL profile."""
        mock_client = MagicMock()
        discoverer = PathDiscoverer(
            http_client=mock_client,
            profile=PathDiscoveryProfile.MINIMAL
        )
        
        assert discoverer.profile == PathDiscoveryProfile.MINIMAL
        assert MINIMAL_MIN_PATHS <= len(discoverer.paths_to_check) <= MINIMAL_MAX_PATHS

    def test_custom_profile_thorough(self):
        """Can initialize with THOROUGH profile."""
        mock_client = MagicMock()
        discoverer = PathDiscoverer(
            http_client=mock_client,
            profile=PathDiscoveryProfile.THOROUGH
        )
        
        assert discoverer.profile == PathDiscoveryProfile.THOROUGH
        assert THOROUGH_MIN_PATHS <= len(discoverer.paths_to_check) <= THOROUGH_MAX_PATHS

    def test_paths_to_check_property(self):
        """paths_to_check property should return the resolved paths."""
        mock_client = MagicMock()
        discoverer = PathDiscoverer(
            http_client=mock_client,
            profile=PathDiscoveryProfile.STANDARD
        )
        
        assert isinstance(discoverer.paths_to_check, list)
        assert discoverer.paths_to_check == discoverer._paths_to_check

    def test_discoverer_paths_match_profile_function(self):
        """PathDiscoverer paths should match get_paths_for_profile output."""
        mock_client = MagicMock()
        
        for profile in PathDiscoveryProfile:
            discoverer = PathDiscoverer(http_client=mock_client, profile=profile)
            expected_paths = get_paths_for_profile(profile)
            
            assert discoverer.paths_to_check == expected_paths, \
                f"Mismatch for profile {profile.name}"


class TestProfileBounds:
    """Tests to ensure profiles stay within their documented bounds."""

    def test_minimal_never_exceeds_max(self):
        """MINIMAL should never exceed 15 paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.MINIMAL)
        assert len(paths) <= MINIMAL_MAX_PATHS, \
            f"MINIMAL exceeds max: {len(paths)} > {MINIMAL_MAX_PATHS}"

    def test_standard_never_exceeds_max(self):
        """STANDARD should never exceed 60 paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.STANDARD)
        assert len(paths) <= STANDARD_MAX_PATHS, \
            f"STANDARD exceeds max: {len(paths)} > {STANDARD_MAX_PATHS}"

    def test_thorough_never_exceeds_max(self):
        """THOROUGH should never exceed 120 paths."""
        paths = get_paths_for_profile(PathDiscoveryProfile.THOROUGH)
        assert len(paths) <= THOROUGH_MAX_PATHS, \
            f"THOROUGH exceeds max: {len(paths)} > {THOROUGH_MAX_PATHS}"

    def test_profiles_are_strictly_ordered_by_size(self):
        """Each profile should have strictly more paths than the previous."""
        minimal = len(get_paths_for_profile(PathDiscoveryProfile.MINIMAL))
        standard = len(get_paths_for_profile(PathDiscoveryProfile.STANDARD))
        thorough = len(get_paths_for_profile(PathDiscoveryProfile.THOROUGH))
        
        assert minimal < standard < thorough, \
            f"Profiles not strictly ordered: MINIMAL({minimal}) < STANDARD({standard}) < THOROUGH({thorough})"


class TestSensitiveMarkers:
    """Tests for the SENSITIVE_MARKERS set."""

    def test_sensitive_markers_not_empty(self):
        """SENSITIVE_MARKERS should contain entries."""
        assert len(PathDiscoverer.SENSITIVE_MARKERS) > 0

    def test_original_markers_preserved(self):
        """Original sensitive markers should still be present."""
        original_markers = {"/admin", "/.env", "/.git/HEAD", "/backup.zip", "/phpinfo.php", "/config"}
        for marker in original_markers:
            assert marker in PathDiscoverer.SENSITIVE_MARKERS, \
                f"Original marker missing: {marker}"

    def test_sensitive_markers_are_valid_paths(self):
        """All sensitive markers should be valid path formats."""
        for marker in PathDiscoverer.SENSITIVE_MARKERS:
            assert isinstance(marker, str)
            assert marker.startswith("/")


class TestLoginPatterns:
    """Tests for the LOGIN_PATTERNS list."""

    def test_login_patterns_not_empty(self):
        """LOGIN_PATTERNS should contain entries."""
        assert len(PathDiscoverer.LOGIN_PATTERNS) > 0

    def test_original_patterns_preserved(self):
        """Original login patterns should still be present."""
        original_patterns = [
            "/login", "/signin", "/sign-in",
            "/auth/login", "/auth/signin",
            "/account/login", "/user/login"
        ]
        for pattern in original_patterns:
            assert pattern in PathDiscoverer.LOGIN_PATTERNS, \
                f"Original pattern missing: {pattern}"


class TestBackwardCompatibility:
    """Tests ensuring backward compatibility."""

    def test_discoverer_works_without_profile_arg(self):
        """PathDiscoverer should work when profile is not specified."""
        mock_client = MagicMock()
        discoverer = PathDiscoverer(http_client=mock_client)
        
        assert discoverer.profile == PathDiscoveryProfile.STANDARD
        assert len(discoverer.paths_to_check) > 0

    def test_discoverer_works_without_log_callback(self):
        """PathDiscoverer should work when log_callback is not specified."""
        mock_client = MagicMock()
        discoverer = PathDiscoverer(http_client=mock_client, profile=PathDiscoveryProfile.MINIMAL)
        
        assert discoverer.log_callback is None
        assert len(discoverer.paths_to_check) > 0

    def test_original_paths_included_in_standard(self):
        """Original PATHS_TO_CHECK paths should be in STANDARD profile."""
        original_paths = [
            "/admin", "/login", "/auth", "/dashboard", "/api",
            "/config", "/backup", "/backup.zip", "/phpinfo.php",
            "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml"
        ]
        standard_paths = set(get_paths_for_profile(PathDiscoveryProfile.STANDARD))
        
        for path in original_paths:
            assert path in standard_paths, f"Original path missing from STANDARD: {path}"


# =============================================================================
# Path Count Reporting (for documentation/debugging)
# =============================================================================

class TestPathCountReporting:
    """Informational tests that report exact path counts."""

    def test_report_actual_path_counts(self):
        """Report the actual path counts for each profile."""
        minimal = len(get_paths_for_profile(PathDiscoveryProfile.MINIMAL))
        standard = len(get_paths_for_profile(PathDiscoveryProfile.STANDARD))
        thorough = len(get_paths_for_profile(PathDiscoveryProfile.THOROUGH))
        
        print(f"\n=== Path Discovery Profile Counts ===")
        print(f"MINIMAL:  {minimal} paths (target: {MINIMAL_MIN_PATHS}-{MINIMAL_MAX_PATHS})")
        print(f"STANDARD: {standard} paths (target: {STANDARD_MIN_PATHS}-{STANDARD_MAX_PATHS})")
        print(f"THOROUGH: {thorough} paths (target: {THOROUGH_MIN_PATHS}-{THOROUGH_MAX_PATHS})")
        print(f"=====================================\n")
        
        # This test always passes - it's for reporting only
        assert True
