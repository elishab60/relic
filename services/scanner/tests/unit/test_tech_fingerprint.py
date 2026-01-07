"""
Unit tests for Tech Fingerprinting module.

Tests:
- Header-based detection (server, x-powered-by, CDN headers, etc.)
- HTML-based detection (Next.js, Nuxt, WordPress, etc.)
- Confidence scoring
- Evidence collection
- Detection merging
- Edge cases (empty responses, blocked, etc.)
"""

import pytest
from datetime import datetime
from typing import Dict, Any

from app.scanner.tech_fingerprint import (
    TechDetection,
    TechFingerprintResult,
    _detect_from_headers,
    _detect_from_html,
    _detect_from_404,
    _redact_sensitive_headers,
    detect_technologies,
)


# =============================================================================
# FIXTURES - Sample headers and HTML content for various technologies
# =============================================================================

@pytest.fixture
def nextjs_headers() -> Dict[str, str]:
    """Headers from a typical Next.js on Vercel deployment."""
    return {
        "Content-Type": "text/html; charset=utf-8",
        "X-Powered-By": "Next.js",
        "X-Vercel-Id": "iad1::abc123-1234567890",
        "X-Vercel-Cache": "HIT",
        "Cache-Control": "public, max-age=0, must-revalidate",
        "Server": "Vercel",
        "CF-Ray": "8abc123def456-IAD",
        "Set-Cookie": "__cf_bm=xyz; path=/; secure; HttpOnly",
    }


@pytest.fixture
def nextjs_html() -> str:
    """HTML content from a Next.js application."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Next.js App</title>
    <script src="/_next/static/chunks/webpack-abc123.js"></script>
</head>
<body>
    <div id="__next">
        <main>Hello World</main>
    </div>
    <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{}}}</script>
    <script async src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXXX"></script>
</body>
</html>
"""


@pytest.fixture
def nuxtjs_headers() -> Dict[str, str]:
    """Headers from a Nuxt.js deployment."""
    return {
        "Content-Type": "text/html; charset=utf-8",
        "X-Powered-By": "Nuxt",
        "Server": "nginx",
        "X-Cache": "MISS",
    }


@pytest.fixture
def nuxtjs_html() -> str:
    """HTML content from a Nuxt.js application."""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Nuxt App</title>
</head>
<body>
    <div id="__nuxt">
        <div id="__layout">Content</div>
    </div>
    <script>window.__NUXT__=(function(a,b){return {data:[],state:{},serverRendered:true}})</script>
    <script src="/_nuxt/app.js"></script>
</body>
</html>
"""


@pytest.fixture
def wordpress_headers() -> Dict[str, str]:
    """Headers from a WordPress site."""
    return {
        "Content-Type": "text/html; charset=UTF-8",
        "Server": "Apache/2.4.52 (Ubuntu)",
        "X-Powered-By": "PHP/8.1.2",
        "Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"',
        "Set-Cookie": "wordpress_test_cookie=WP+Cookie+check; path=/",
    }


@pytest.fixture
def wordpress_html() -> str:
    """HTML content from a WordPress site."""
    return """
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta name="generator" content="WordPress 6.4.2" />
    <link rel="stylesheet" href="https://example.com/wp-content/themes/mytheme/style.css" type="text/css" />
    <script src="https://example.com/wp-includes/js/jquery/jquery.min.js"></script>
</head>
<body class="home page">
    <div id="content">
        <article class="post type-post">
            <h1>Hello World</h1>
        </article>
    </div>
    <script async src="https://www.googletagmanager.com/gtag/js?id=UA-XXXXXXX-X"></script>
</body>
</html>
"""


@pytest.fixture
def cloudflare_blocked_headers() -> Dict[str, str]:
    """Headers from a Cloudflare WAF challenge page."""
    return {
        "Content-Type": "text/html; charset=UTF-8",
        "CF-Ray": "8abc123def456-IAD",
        "Server": "cloudflare",
        "X-Frame-Options": "SAMEORIGIN",
        "CF-Mitigated": "challenge",
    }


@pytest.fixture
def shopify_headers() -> Dict[str, str]:
    """Headers from a Shopify store."""
    return {
        "Content-Type": "text/html; charset=utf-8",
        "X-Shopify-Stage": "production",
        "X-Shopify-Request-Id": "abc123-def456-ghi789",
        "Server": "Shopify",
        "X-Content-Type-Options": "nosniff",
        "Set-Cookie": "_shopify_s=abc123; path=/; secure",
    }


@pytest.fixture
def shopify_html() -> str:
    """HTML content from a Shopify store."""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>My Shop</title>
    <script src="https://cdn.shopify.com/s/files/1/0001/0001/files/theme.js"></script>
</head>
<body>
    <div id="shopify-section-header">
        <header>Store Header</header>
    </div>
    <script>
        Shopify.theme = {"name": "Dawn"};
    </script>
</body>
</html>
"""


@pytest.fixture
def react_vue_mixed_html() -> str:
    """HTML with both React and Vue markers (edge case)."""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Mixed App</title>
    <script src="/js/react.production.min.js"></script>
</head>
<body>
    <div data-reactroot>
        <div data-v-abc12345>Vue component inside React?</div>
    </div>
</body>
</html>
"""


@pytest.fixture
def django_404_body() -> str:
    """Django 404 error page body."""
    return """
<!DOCTYPE html>
<html lang="en">
<head><title>Page not found - Django</title></head>
<body>
<h1>Page not found</h1>
<p>The requested resource was not found on this server.</p>
</body>
</html>
"""


@pytest.fixture
def rails_404_body() -> str:
    """Rails 404 error page body."""
    return """
<!DOCTYPE html>
<html>
<head><title>The page you're looking for doesn't exist</title></head>
<body>
<p>You may have mistyped the address or the page may have moved.</p>
</body>
</html>
"""


# =============================================================================
# TESTS - Header Detection
# =============================================================================

class TestHeaderDetection:
    """Tests for header-based technology detection."""

    def test_nextjs_vercel_cloudflare_stack(self, nextjs_headers):
        """Detect full Next.js + Vercel + Cloudflare stack from headers."""
        detections = _detect_from_headers(nextjs_headers)
        
        tech_names = [d.name for d in detections]
        
        assert "Next.js" in tech_names, "Should detect Next.js from x-powered-by"
        assert "Vercel" in tech_names, "Should detect Vercel from x-vercel-id"
        assert "Cloudflare" in tech_names, "Should detect Cloudflare from cf-ray"
        
        # Check confidence levels
        nextjs_det = next(d for d in detections if d.name == "Next.js")
        assert nextjs_det.confidence == "high"
        assert nextjs_det.category == "frontend_framework"
        assert len(nextjs_det.evidence) > 0

    def test_wordpress_php_apache(self, wordpress_headers):
        """Detect WordPress stack: Apache + PHP."""
        detections = _detect_from_headers(wordpress_headers)
        
        tech_names = [d.name for d in detections]
        
        assert "Apache" in tech_names
        assert "PHP" in tech_names
        
        # Check Apache detection
        apache_det = next(d for d in detections if d.name == "Apache")
        assert apache_det.category == "server"
        assert apache_det.confidence == "high"

    def test_shopify_detection(self, shopify_headers):
        """Detect Shopify from its custom headers."""
        detections = _detect_from_headers(shopify_headers)
        
        tech_names = [d.name for d in detections]
        
        assert "Shopify" in tech_names
        
        shopify_det = next(d for d in detections if d.name == "Shopify")
        assert shopify_det.category == "ecommerce"
        assert shopify_det.confidence == "high"

    def test_nuxtjs_nginx(self, nuxtjs_headers):
        """Detect Nuxt.js with nginx."""
        detections = _detect_from_headers(nuxtjs_headers)
        
        tech_names = [d.name for d in detections]
        
        assert "Nuxt.js" in tech_names
        assert "nginx" in tech_names
        
    def test_cloudflare_blocked(self, cloudflare_blocked_headers):
        """Detect Cloudflare even when blocking."""
        detections = _detect_from_headers(cloudflare_blocked_headers)
        
        tech_names = [d.name for d in detections]
        
        assert "Cloudflare" in tech_names
        assert "cloudflare" in [d.name.lower() for d in detections if d.category == "cdn" or d.category == "server"]

    def test_empty_headers(self):
        """Handle empty headers gracefully."""
        detections = _detect_from_headers({})
        assert detections == []

    def test_case_insensitive_header_names(self):
        """Header names should be case-insensitive."""
        headers = {
            "X-POWERED-BY": "Express",  # uppercase
            "server": "nginx",  # lowercase
        }
        detections = _detect_from_headers(headers)
        tech_names = [d.name for d in detections]
        
        assert "Express.js" in tech_names
        assert "nginx" in tech_names


# =============================================================================
# TESTS - HTML Detection
# =============================================================================

class TestHTMLDetection:
    """Tests for HTML-based technology detection."""

    def test_nextjs_markers(self, nextjs_html):
        """Detect Next.js from HTML markers."""
        detections = _detect_from_html(nextjs_html)
        
        tech_names = [d.name for d in detections]
        
        assert "Next.js" in tech_names, "Should detect __NEXT_DATA__ marker"
        assert "Google Tag Manager" in tech_names, "Should detect GTM"

    def test_nuxtjs_markers(self, nuxtjs_html):
        """Detect Nuxt.js from HTML markers."""
        detections = _detect_from_html(nuxtjs_html)
        
        tech_names = [d.name for d in detections]
        
        assert "Nuxt.js" in tech_names
        
        nuxt_det = next(d for d in detections if d.name == "Nuxt.js")
        assert nuxt_det.confidence == "high"

    def test_wordpress_markers(self, wordpress_html):
        """Detect WordPress from HTML markers."""
        detections = _detect_from_html(wordpress_html)
        
        tech_names = [d.name for d in detections]
        
        assert "WordPress" in tech_names
        assert "jQuery" in tech_names
        # The fixture uses googletagmanager.com/gtag/ which matches Google Tag Manager pattern
        assert "Google Tag Manager" in tech_names or "Google Analytics (gtag)" in tech_names

    def test_wordpress_version_extraction(self, wordpress_html):
        """Extract WordPress version from generator meta tag."""
        detections = _detect_from_html(wordpress_html)
        
        wp_detections = [d for d in detections if d.name == "WordPress"]
        
        # At least one should have version
        versions = [d.version for d in wp_detections if d.version]
        assert any(v and "6.4" in v for v in versions), f"Should extract WP version, got: {versions}"

    def test_shopify_cdn_detection(self, shopify_html):
        """Detect Shopify from CDN references."""
        detections = _detect_from_html(shopify_html)
        
        tech_names = [d.name for d in detections]
        
        assert "Shopify" in tech_names

    def test_react_vue_mixed(self, react_vue_mixed_html):
        """Detect multiple frameworks in same page (edge case)."""
        detections = _detect_from_html(react_vue_mixed_html)
        
        tech_names = [d.name for d in detections]
        
        assert "React" in tech_names
        assert "Vue.js" in tech_names

    def test_empty_html(self):
        """Handle empty HTML gracefully."""
        detections = _detect_from_html("")
        assert detections == []

    def test_evidence_snippet_creation(self, nextjs_html):
        """Verify evidence snippets are created correctly."""
        detections = _detect_from_html(nextjs_html)
        
        for det in detections:
            for evidence in det.evidence:
                assert "html_marker:" in evidence
                assert len(evidence) <= 300, "Evidence should be reasonably sized"


# =============================================================================
# TESTS - 404 Probe Detection
# =============================================================================

class Test404Detection:
    """Tests for 404 error page framework detection."""

    def test_django_404_signature(self, django_404_body):
        """Detect Django from 404 page."""
        detections = _detect_from_404(django_404_body, 404)
        
        tech_names = [d.name for d in detections]
        
        assert "Django" in tech_names
        
        django_det = next(d for d in detections if d.name == "Django")
        assert django_det.category == "backend_runtime"
        assert "404_probe" in django_det.evidence[0]

    def test_rails_404_signature(self, rails_404_body):
        """Detect Rails from 404 page."""
        detections = _detect_from_404(rails_404_body, 404)
        
        tech_names = [d.name for d in detections]
        
        assert "Ruby on Rails" in tech_names

    def test_generic_404_no_detection(self):
        """Generic 404 pages should yield no detections."""
        generic_404 = "<html><body><h1>Not Found</h1></body></html>"
        detections = _detect_from_404(generic_404, 404)
        
        assert len(detections) == 0


# =============================================================================
# TESTS - TechFingerprintResult
# =============================================================================

class TestTechFingerprintResult:
    """Tests for TechFingerprintResult model."""

    def test_merge_detection_new_tech(self):
        """Merge adds new technology if not present."""
        result = TechFingerprintResult()
        
        det = TechDetection(
            name="React",
            category="javascript_library",
            confidence="medium",
            evidence=["html_marker: data-reactroot"]
        )
        
        result.merge_detection(det)
        
        assert len(result.technologies) == 1
        assert result.technologies[0].name == "React"

    def test_merge_detection_upgrade_confidence(self):
        """Merging should upgrade confidence if new is higher."""
        result = TechFingerprintResult()
        
        det1 = TechDetection(
            name="Next.js",
            category="frontend_framework",
            confidence="low",
            evidence=["header: x-powered-by"]
        )
        result.merge_detection(det1)
        
        det2 = TechDetection(
            name="Next.js",
            category="frontend_framework",
            confidence="high",
            evidence=["html_marker: __NEXT_DATA__"]
        )
        result.merge_detection(det2)
        
        assert len(result.technologies) == 1
        assert result.technologies[0].confidence == "high"
        assert len(result.technologies[0].evidence) == 2

    def test_merge_detection_combine_evidence(self):
        """Merging should combine evidence from both detections."""
        result = TechFingerprintResult()
        
        det1 = TechDetection(
            name="WordPress",
            category="cms",
            confidence="high",
            evidence=["header: x-generator"]
        )
        result.merge_detection(det1)
        
        det2 = TechDetection(
            name="wordpress",  # lowercase - should still match
            category="cms",
            confidence="high",
            evidence=["html_marker: wp-content"]
        )
        result.merge_detection(det2)
        
        assert len(result.technologies) == 1
        assert len(result.technologies[0].evidence) == 2
        assert result.technologies[0].source == "merged"

    def test_generate_summary(self):
        """Summary groups technologies by category."""
        result = TechFingerprintResult(technologies=[
            TechDetection(name="Next.js", category="frontend_framework", confidence="high"),
            TechDetection(name="React", category="javascript_library", confidence="medium"),
            TechDetection(name="Vercel", category="hosting", confidence="high"),
            TechDetection(name="Cloudflare", category="cdn", confidence="high"),
        ])
        
        summary = result._generate_summary()
        
        assert "frontend_framework" in summary
        assert "Next.js" in summary["frontend_framework"]
        assert "cdn" in summary
        assert "Cloudflare" in summary["cdn"]

    def test_get_by_category(self):
        """Filter technologies by category."""
        result = TechFingerprintResult(technologies=[
            TechDetection(name="Next.js", category="frontend_framework", confidence="high"),
            TechDetection(name="Vercel", category="hosting", confidence="high"),
            TechDetection(name="Cloudflare", category="cdn", confidence="high"),
        ])
        
        hosting = result.get_by_category("hosting")
        
        assert len(hosting) == 1
        assert hosting[0].name == "Vercel"

    def test_to_dict_serialization(self):
        """Verify to_dict produces valid JSON-serializable output."""
        result = TechFingerprintResult(
            technologies=[
                TechDetection(
                    name="Next.js",
                    category="frontend_framework",
                    confidence="high",
                    evidence=["header test"],
                    version="14.0.0"
                )
            ],
            blocked_by_waf=False,
            probe_failures=[],
            detection_methods=["header_analysis", "html_analysis"]
        )
        
        data = result.to_dict()
        
        assert "technologies" in data
        assert "summary" in data
        assert "detection_methods" in data
        assert len(data["technologies"]) == 1
        assert data["technologies"][0]["name"] == "Next.js"
        assert data["technologies"][0]["version"] == "14.0.0"


# =============================================================================
# TESTS - Header Redaction
# =============================================================================

class TestHeaderRedaction:
    """Tests for sensitive header redaction."""

    def test_redacts_authorization(self):
        """Redact Authorization header."""
        headers = {"Authorization": "Bearer secret-token-12345"}
        redacted = _redact_sensitive_headers(headers)
        
        assert redacted["Authorization"] == "[REDACTED]"

    def test_redacts_cookies(self):
        """Redact Cookie header."""
        headers = {"Cookie": "session=abc123; user=john"}
        redacted = _redact_sensitive_headers(headers)
        
        assert redacted["Cookie"] == "[REDACTED]"

    def test_preserves_safe_headers(self):
        """Safe headers should not be redacted."""
        headers = {
            "Content-Type": "text/html",
            "Server": "nginx",
            "X-Powered-By": "Next.js"
        }
        redacted = _redact_sensitive_headers(headers)
        
        assert redacted["Content-Type"] == "text/html"
        assert redacted["Server"] == "nginx"
        assert redacted["X-Powered-By"] == "Next.js"

    def test_truncates_long_values(self):
        """Long header values should be truncated."""
        long_value = "x" * 500
        headers = {"X-Custom": long_value}
        redacted = _redact_sensitive_headers(headers)
        
        assert len(redacted["X-Custom"]) < len(long_value)
        assert "[TRUNCATED]" in redacted["X-Custom"]


# =============================================================================
# TESTS - Integration (detect_technologies)
# =============================================================================

class TestDetectTechnologies:
    """Tests for the main detect_technologies function."""

    @pytest.mark.asyncio
    async def test_full_detection_nextjs(self, nextjs_headers, nextjs_html):
        """Full detection for Next.js site."""
        result = await detect_technologies(
            url="https://example.com",
            html=nextjs_html,
            headers=nextjs_headers,
            http_client=None,
            perform_404_probe=False
        )
        
        tech_names = [t.name for t in result.technologies]
        
        assert "Next.js" in tech_names
        assert "Vercel" in tech_names
        assert "Cloudflare" in tech_names
        assert "Google Tag Manager" in tech_names
        
        assert "header_analysis" in result.detection_methods
        assert "html_analysis" in result.detection_methods

    @pytest.mark.asyncio
    async def test_full_detection_wordpress(self, wordpress_headers, wordpress_html):
        """Full detection for WordPress site."""
        result = await detect_technologies(
            url="https://example.com",
            html=wordpress_html,
            headers=wordpress_headers,
            http_client=None,
            perform_404_probe=False
        )
        
        tech_names = [t.name for t in result.technologies]
        
        assert "WordPress" in tech_names
        assert "PHP" in tech_names
        assert "Apache" in tech_names
        assert "jQuery" in tech_names

    @pytest.mark.asyncio
    async def test_blocked_detection(self, cloudflare_blocked_headers):
        """Detection when blocked by WAF."""
        result = await detect_technologies(
            url="https://example.com",
            html="<html><body>Challenge</body></html>",
            headers=cloudflare_blocked_headers,
            http_client=None,
            perform_404_probe=False
        )
        
        # Should still detect Cloudflare
        tech_names = [t.name for t in result.technologies]
        assert "Cloudflare" in tech_names

    @pytest.mark.asyncio
    async def test_raw_headers_sample_included(self, nextjs_headers, nextjs_html):
        """Raw headers sample should be included in result."""
        result = await detect_technologies(
            url="https://example.com",
            html=nextjs_html,
            headers=nextjs_headers,
            http_client=None,
            perform_404_probe=False
        )
        
        assert result.raw_headers_sample is not None
        assert "Content-Type" in result.raw_headers_sample


# =============================================================================
# TESTS - Edge Cases & Error Handling
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_malformed_regex_patterns(self):
        """Malformed patterns in HTML should not crash."""
        # This is testing that our patterns don't break on weird HTML
        weird_html = "<script>var x = /(a+b*</script>"  # Broken regex in content
        
        # Should not raise
        detections = _detect_from_html(weird_html)
        assert isinstance(detections, list)

    def test_unicode_content(self):
        """Unicode content should be handled."""
        unicode_html = """
<html>
<head><title>日本語サイト</title></head>
<body>
    <div data-reactroot>React アプリ</div>
    <script src="/_next/static/chunks/main.js"></script>
</body>
</html>
"""
        detections = _detect_from_html(unicode_html)
        
        tech_names = [d.name for d in detections]
        
        assert "React" in tech_names
        assert "Next.js" in tech_names

    def test_very_large_html(self):
        """Large HTML content should be handled without memory issues."""
        # Generate large HTML
        large_html = "<html><body>" + "x" * 1_000_000 + "<div data-reactroot></div></body></html>"
        
        detections = _detect_from_html(large_html)
        
        tech_names = [d.name for d in detections]
        assert "React" in tech_names

    def test_detection_deduplication(self):
        """Same technology from multiple patterns should be merged."""
        # HTML with multiple Next.js markers
        html = """
<script id="__NEXT_DATA__">{"props":{}}</script>
<script src="/_next/static/chunks/webpack.js"></script>
<script>__NEXT_LOADED_PAGES__=[]</script>
"""
        detections = _detect_from_html(html)
        
        # Should all be Next.js
        nextjs_detections = [d for d in detections if d.name == "Next.js"]
        
        # Verify we got multiple pieces of evidence
        assert len(nextjs_detections) >= 1
        
        # When merged via TechFingerprintResult, should combine
        result = TechFingerprintResult()
        for det in detections:
            result.merge_detection(det)
        
        nextjs_in_result = [t for t in result.technologies if t.name == "Next.js"]
        assert len(nextjs_in_result) == 1  # Merged into one
        assert len(nextjs_in_result[0].evidence) >= 2  # Multiple evidence pieces
