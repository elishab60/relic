"""
Unit tests for PR-03: Evidence & Reproducibility Hardening

Tests for:
- Finding model evidence contract enforcement
- Confidence field requirements
- repro_curl presence for actionable findings
"""

import pytest
from app.scanner.models import Finding
from app.constants import Severity, Category


class TestFindingEvidenceContract:
    """Tests for evidence contract enforcement in Finding model."""
    
    def test_valid_high_severity_xss_finding_keeps_severity(self):
        """A valid HIGH severity XSS finding with evidence and repro_curl keeps its severity."""
        finding = Finding(
            title="Reflected XSS",
            severity=Severity.HIGH,
            category=Category.XSS,
            description="Test XSS",
            recommendation="Encode output",
            evidence="Payload reflected",
            repro_curl="curl http://example.com/page?q=<script>",
            confidence="high"
        )
        assert finding.severity == Severity.HIGH
        assert finding.confidence == "high"
    
    def test_xss_finding_without_evidence_downgrades(self):
        """XSS finding without evidence should downgrade to INFO."""
        finding = Finding(
            title="Reflected XSS",
            severity=Severity.HIGH,
            category=Category.XSS,
            description="Test XSS",
            recommendation="Encode output",
            # No evidence
            repro_curl="curl http://example.com/page?q=<script>",
            confidence="high"
        )
        assert finding.severity == Severity.INFO
        assert finding.confidence == "low"
    
    def test_xss_finding_without_repro_curl_downgrades(self):
        """XSS finding without repro_curl should downgrade to INFO."""
        finding = Finding(
            title="Reflected XSS",
            severity=Severity.HIGH,
            category=Category.XSS,
            description="Test XSS",
            recommendation="Encode output",
            evidence="Payload reflected",
            # No repro_curl
            confidence="high"
        )
        assert finding.severity == Severity.INFO
        assert finding.confidence == "low"
    
    def test_low_severity_finding_not_enforced(self):
        """LOW severity findings don't require evidence contract."""
        finding = Finding(
            title="Info Disclosure",
            severity=Severity.LOW,
            category=Category.EXPOSURE,
            description="Server header exposed",
            recommendation="Remove header",
            # No evidence or repro_curl
            confidence="low"
        )
        assert finding.severity == Severity.LOW
        assert finding.confidence == "low"
    
    def test_non_actionable_category_not_enforced(self):
        """Non-actionable categories (TLS) don't require repro_curl."""
        finding = Finding(
            title="HTTPS not enforced",
            severity=Severity.HIGH,
            category=Category.TLS,
            description="HTTP accessible",
            recommendation="Force HTTPS",
            evidence="HTTP URL accessible",
            # No repro_curl - should be fine for TLS
            confidence="high"
        )
        assert finding.severity == Severity.HIGH
        assert finding.confidence == "high"
    
    def test_sqli_finding_with_evidence_snippet_counts(self):
        """evidence_snippet should count as evidence."""
        finding = Finding(
            title="SQL Injection",
            severity=Severity.HIGH,
            category=Category.SQLI,
            description="Error-based SQLi",
            recommendation="Use parameterized queries",
            # No evidence, but has evidence_snippet
            evidence_snippet="redacted snippet",
            repro_curl="curl http://example.com/page?id=1'",
            confidence="high"
        )
        assert finding.severity == Severity.HIGH


class TestReproCurl:
    """Tests for repro_curl format."""
    
    def test_xss_repro_curl_starts_with_curl(self):
        """repro_curl should start with 'curl '."""
        finding = Finding(
            title="Reflected XSS",
            severity=Severity.HIGH,
            category=Category.XSS,
            description="Test",
            recommendation="Test",
            evidence="Test",
            repro_curl="curl http://example.com",
            confidence="high"
        )
        assert finding.repro_curl.startswith("curl ")
    
    def test_informational_finding_no_repro_curl(self):
        """Informational findings should not have repro_curl."""
        finding = Finding(
            title="Server Header",
            severity=Severity.INFO,
            category=Category.EXPOSURE,
            description="Test",
            recommendation="Test",
            evidence="Test",
            confidence="low"
            # No repro_curl
        )
        assert finding.repro_curl is None


class TestConfidenceField:
    """Tests for confidence field."""
    
    def test_confidence_defaults_to_medium(self):
        """Confidence should default to 'medium'."""
        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            category=Category.EXPOSURE,
            description="Test",
            recommendation="Test"
        )
        assert finding.confidence == "medium"
    
    def test_confidence_can_be_set(self):
        """Confidence can be set to low, medium, or high."""
        for conf in ["low", "medium", "high"]:
            finding = Finding(
                title="Test",
                severity=Severity.INFO,
                category=Category.EXPOSURE,
                description="Test",
                recommendation="Test",
                confidence=conf
            )
            assert finding.confidence == conf


class TestSeverityComparison:
    """Tests for Severity enum comparison."""
    
    def test_severity_ordering(self):
        """Severity levels should be orderable."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
    
    def test_severity_ge_medium(self):
        """Test >= MEDIUM comparison."""
        assert Severity.MEDIUM >= Severity.MEDIUM
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.CRITICAL >= Severity.MEDIUM
        assert not (Severity.LOW >= Severity.MEDIUM)
        assert not (Severity.INFO >= Severity.MEDIUM)
