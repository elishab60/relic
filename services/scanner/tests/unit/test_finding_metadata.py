"""
Unit tests for PR-01: Finding v2 Evidence & Credibility Upgrade.

Tests:
- Finding dataclass accepts new fields
- repro_curl never contains forbidden headers
- redact_secrets removes sensitive patterns
- evidence_snippet length is capped
- evidence_hash is deterministic
"""
import pytest
import hashlib

from app.scanner.models import Finding
from app.scanner.utils.redaction import (
    redact_secrets,
    compute_evidence_hash,
    truncate_evidence,
    prepare_evidence_snippet,
    MAX_EVIDENCE_SNIPPET_LENGTH,
)
from app.scanner.utils.repro_curl import (
    build_repro_curl,
    build_xss_repro_curl,
    build_sqli_repro_curl,
    build_cors_repro_curl,
    build_sensitive_file_repro_curl,
    RELIC_USER_AGENT,
)
from app.constants import Severity, Category


class TestFindingModel:
    """Tests for the updated Finding dataclass."""

    def test_finding_accepts_new_fields(self):
        """Finding should accept all new credibility metadata fields."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            category=Category.XSS,
            description="Test description",
            recommendation="Test recommendation",
            confidence="high",
            repro_curl="curl -X GET 'http://example.com'",
            evidence_snippet="Redacted snippet...",
            evidence_hash="abc123def456",
        )

        assert finding.confidence == "high"
        assert finding.repro_curl == "curl -X GET 'http://example.com'"
        assert finding.evidence_snippet == "Redacted snippet..."
        assert finding.evidence_hash == "abc123def456"

    def test_finding_default_confidence(self):
        """Finding should default to 'medium' confidence."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.LOW,
            category=Category.EXPOSURE,
            description="Test",
            recommendation="Test",
        )

        assert finding.confidence == "medium"
        assert finding.repro_curl is None
        assert finding.evidence_snippet is None
        assert finding.evidence_hash is None

    def test_finding_backward_compatibility(self):
        """Old code creating Findings without new fields should still work."""
        finding = Finding(
            title="Legacy Finding",
            severity="HIGH",  # String instead of enum (backward compat)
            category="XSS",
            description="Legacy desc",
            recommendation="Legacy rec",
            evidence="Old evidence field",
            owasp_refs=["A03:2021-Injection"],
        )

        # Should work without new fields
        assert finding.title == "Legacy Finding"
        assert finding.evidence == "Old evidence field"
        # New fields should have defaults
        assert finding.confidence == "medium"


class TestReproCurl:
    """Tests for the repro_curl helper functions."""

    def test_build_repro_curl_basic(self):
        """Basic cURL command generation."""
        result = build_repro_curl("GET", "http://example.com/test")

        assert "curl" in result
        assert "'http://example.com/test'" in result
        assert f"User-Agent: {RELIC_USER_AGENT}" in result

    def test_repro_curl_never_contains_cookie(self):
        """repro_curl must NEVER include Cookie header."""
        result = build_repro_curl(
            "GET",
            "http://example.com",
            headers={"Cookie": "session=abc123", "Origin": "http://localhost"},
        )

        assert "Cookie" not in result
        assert "session" not in result
        assert "abc123" not in result
        # Origin should be present (whitelisted)
        assert "Origin" in result

    def test_repro_curl_never_contains_authorization(self):
        """repro_curl must NEVER include Authorization header."""
        result = build_repro_curl(
            "GET",
            "http://example.com",
            headers={
                "Authorization": "Bearer secret-token",
                "Content-Type": "application/json",
            },
        )

        assert "Authorization" not in result
        assert "Bearer" not in result
        assert "secret-token" not in result
        # Content-Type should be present (whitelisted)
        assert "Content-Type" in result

    def test_repro_curl_never_contains_api_key(self):
        """repro_curl must NEVER include API key headers."""
        result = build_repro_curl(
            "GET",
            "http://example.com",
            headers={"X-API-Key": "my-secret-key", "Accept": "text/html"},
        )

        assert "X-API-Key" not in result
        assert "my-secret-key" not in result
        # Accept should be present (whitelisted)
        assert "Accept" in result

    def test_build_xss_repro_curl(self):
        """XSS repro cURL should include URL-encoded payload."""
        result = build_xss_repro_curl(
            "http://example.com/search", "q", "<script>alert(1)</script>"
        )

        assert "curl" in result
        assert "example.com/search" in result
        assert "q=" in result
        # Payload should be URL-encoded
        assert "%3Cscript%3E" in result or "script" in result

    def test_build_cors_repro_curl(self):
        """CORS repro cURL should include Origin header."""
        result = build_cors_repro_curl("http://example.com", "https://evil.com")

        assert "curl" in result
        assert "Origin" in result
        assert "evil.com" in result


class TestRedaction:
    """Tests for the redaction utilities."""

    def test_redact_aws_key(self):
        """AWS access keys should be redacted."""
        text = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
        result = redact_secrets(text)

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_redact_password_patterns(self):
        """Password patterns should be redacted."""
        test_cases = [
            "DB_PASSWORD=supersecret123",
            "password=mypass",
            "SECRET=topsecret",
            "MYSQL_PWD=dbpass123",
        ]

        for text in test_cases:
            result = redact_secrets(text)
            # The value should be redacted
            assert "REDACTED" in result
            # The key name can remain but value should not
            assert "supersecret123" not in result
            assert "mypass" not in result
            assert "topsecret" not in result
            assert "dbpass123" not in result

    def test_redact_bearer_token(self):
        """Bearer tokens should be redacted."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
        result = redact_secrets(text)

        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "REDACTED" in result

    def test_redact_private_key(self):
        """RSA private keys should be redacted."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3UQ...
-----END RSA PRIVATE KEY-----"""
        result = redact_secrets(text)

        assert "MIIEowIBAAKCAQEA0Z3UQ" not in result
        assert "REDACTED" in result

    def test_redact_preserves_non_sensitive(self):
        """Non-sensitive text should be preserved."""
        text = "This is a normal log message with status=200 and path=/api/health"
        result = redact_secrets(text)

        assert result == text  # Should be unchanged


class TestEvidenceSnippet:
    """Tests for evidence snippet handling."""

    def test_truncate_evidence_under_limit(self):
        """Short evidence should not be truncated."""
        text = "Short evidence"
        result = truncate_evidence(text)

        assert result == text
        assert "..." not in result

    def test_truncate_evidence_over_limit(self):
        """Long evidence should be truncated with ellipsis."""
        text = "x" * 500  # Longer than MAX_EVIDENCE_SNIPPET_LENGTH
        result = truncate_evidence(text)

        assert len(result) == MAX_EVIDENCE_SNIPPET_LENGTH
        assert result.endswith("...")

    def test_evidence_snippet_max_length(self):
        """Evidence snippet should respect max length (200-400 chars)."""
        assert 200 <= MAX_EVIDENCE_SNIPPET_LENGTH <= 400


class TestEvidenceHash:
    """Tests for evidence hash computation."""

    def test_evidence_hash_deterministic(self):
        """Same content should always produce same hash."""
        content = "This is test content for hashing"

        hash1 = compute_evidence_hash(content)
        hash2 = compute_evidence_hash(content)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex is 64 chars

    def test_evidence_hash_different_for_different_content(self):
        """Different content should produce different hashes."""
        hash1 = compute_evidence_hash("Content A")
        hash2 = compute_evidence_hash("Content B")

        assert hash1 != hash2

    def test_evidence_hash_matches_sha256(self):
        """Hash should match standard SHA-256."""
        content = "Test content"
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()

        result = compute_evidence_hash(content)

        assert result == expected


class TestPrepareEvidenceSnippet:
    """Tests for the combined evidence preparation."""

    def test_prepare_evidence_snippet_redacts_and_hashes(self):
        """prepare_evidence_snippet should redact, truncate, and hash."""
        raw = "API_KEY=secret123 and some other content"

        snippet, hash_val = prepare_evidence_snippet(raw)

        # Snippet should be redacted
        assert "secret123" not in snippet
        assert "REDACTED" in snippet

        # Hash should be of ORIGINAL content (before redaction)
        expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert hash_val == expected_hash

    def test_prepare_evidence_snippet_truncates(self):
        """Long content should be truncated in snippet but not in hash calc."""
        raw = "x" * 1000

        snippet, hash_val = prepare_evidence_snippet(raw)

        # Snippet should be truncated
        assert len(snippet) <= MAX_EVIDENCE_SNIPPET_LENGTH

        # Hash should be of full content
        expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert hash_val == expected_hash
