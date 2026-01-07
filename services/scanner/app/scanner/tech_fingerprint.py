"""
Tech Fingerprinting Module for RELIC/AUDITAI

Detects web technologies (frameworks, CMS, CDN, WAF, hosting, analytics, etc.)
from HTTP headers and HTML content using:
  1. Wappalyzer Python wrapper (optional, graceful degradation)
  2. Custom heuristics (always active as fallback/complement)

Evidence-first approach: every detection includes proof and confidence level.
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Literal, Any, Callable, Awaitable
from urllib.parse import urlparse
import logging

# Type aliases
ConfidenceLevel = Literal["low", "medium", "high"]
TechCategory = Literal[
    "frontend_framework",
    "backend_runtime", 
    "cms",
    "ecommerce",
    "server",
    "cdn",
    "waf",
    "hosting",
    "analytics",
    "tag_manager",
    "api_style",
    "database",
    "javascript_library",
    "build_tool",
    "unknown"
]

# Logger
logger = logging.getLogger(__name__)


@dataclass
class TechDetection:
    """
    Represents a single detected technology.
    
    Attributes:
        name: Technology name (e.g., "Next.js", "Cloudflare")
        category: Technology category (frontend_framework, cdn, etc.)
        confidence: Detection confidence level (low/medium/high)
        evidence: List of evidence strings (e.g., "header: x-powered-by=Next.js")
        version: Optional detected version
        source: Detection source ("wappalyzer", "heuristic", "merged")
    """
    name: str
    category: TechCategory
    confidence: ConfidenceLevel
    evidence: List[str] = field(default_factory=list)
    version: Optional[str] = None
    source: str = "heuristic"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "version": self.version,
            "source": self.source
        }


@dataclass 
class TechFingerprintResult:
    """
    Complete tech fingerprint result for a target.
    
    Attributes:
        technologies: List of detected technologies
        blocked_by_waf: Whether detection was blocked by WAF/challenge
        probe_failures: List of probe failure messages
        raw_headers_sample: Sample of raw headers (redacted if needed)
        detection_methods: Which detection methods were used
        probe_count: Number of HTTP probes performed
    """
    technologies: List[TechDetection] = field(default_factory=list)
    blocked_by_waf: bool = False
    probe_failures: List[str] = field(default_factory=list)
    raw_headers_sample: Optional[Dict[str, str]] = None
    detection_methods: List[str] = field(default_factory=list)
    probe_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "technologies": [t.to_dict() for t in self.technologies],
            "blocked_by_waf": self.blocked_by_waf,
            "probe_failures": self.probe_failures,
            "raw_headers_sample": self.raw_headers_sample,
            "detection_methods": self.detection_methods,
            "probe_count": self.probe_count,
            "summary": self._generate_summary()
        }
    
    def _generate_summary(self) -> Dict[str, List[str]]:
        """Generate a categorized summary of detected technologies."""
        summary: Dict[str, List[str]] = {}
        for tech in self.technologies:
            cat = tech.category
            if cat not in summary:
                summary[cat] = []
            name = tech.name
            if tech.version:
                name += f" ({tech.version})"
            if name not in summary[cat]:
                summary[cat].append(name)
        return summary
    
    def get_by_category(self, category: TechCategory) -> List[TechDetection]:
        """Get all technologies in a specific category."""
        return [t for t in self.technologies if t.category == category]
    
    def merge_detection(self, detection: TechDetection) -> None:
        """
        Merge a new detection with existing ones.
        If same tech exists, merge evidence and upgrade confidence if needed.
        """
        existing = next(
            (t for t in self.technologies 
             if t.name.lower() == detection.name.lower() and t.category == detection.category),
            None
        )
        
        if existing:
            # Merge evidence
            for ev in detection.evidence:
                if ev not in existing.evidence:
                    existing.evidence.append(ev)
            
            # Upgrade confidence if new is higher
            conf_order = {"low": 0, "medium": 1, "high": 2}
            if conf_order.get(detection.confidence, 0) > conf_order.get(existing.confidence, 0):
                existing.confidence = detection.confidence
            
            # Update version if new and existing doesn't have one
            if detection.version and not existing.version:
                existing.version = detection.version
                
            # Update source to merged
            existing.source = "merged"
        else:
            self.technologies.append(detection)


# =============================================================================
# HEURISTIC PATTERNS - Comprehensive tech detection signatures
# =============================================================================

# Header-based patterns: header_name_lower -> [(regex_pattern, tech_name, category, confidence)]
HEADER_PATTERNS: Dict[str, List[Tuple[str, str, TechCategory, ConfidenceLevel]]] = {
    "server": [
        (r"nginx", "nginx", "server", "high"),
        (r"apache", "Apache", "server", "high"),
        (r"cloudflare", "Cloudflare", "cdn", "high"),
        (r"microsoft-iis", "IIS", "server", "high"),
        (r"litespeed", "LiteSpeed", "server", "high"),
        (r"caddy", "Caddy", "server", "high"),
        (r"openresty", "OpenResty", "server", "high"),
        (r"envoy", "Envoy", "server", "high"),
        (r"gunicorn", "Gunicorn", "server", "medium"),
        (r"uvicorn", "Uvicorn", "server", "medium"),
        (r"waitress", "Waitress", "server", "medium"),
        (r"cowboy", "Cowboy (Erlang)", "server", "medium"),
        (r"jetty", "Jetty", "server", "medium"),
        (r"tomcat", "Tomcat", "server", "medium"),
        (r"kestrel", "Kestrel (.NET)", "server", "medium"),
    ],
    "x-powered-by": [
        (r"next\.?js", "Next.js", "frontend_framework", "high"),
        (r"nuxt", "Nuxt.js", "frontend_framework", "high"),
        (r"express", "Express.js", "backend_runtime", "high"),
        (r"php/?(\d+\.?\d*)?", "PHP", "backend_runtime", "high"),
        (r"asp\.net", "ASP.NET", "backend_runtime", "high"),
        (r"flask", "Flask", "backend_runtime", "medium"),
        (r"django", "Django", "backend_runtime", "medium"),
        (r"rails", "Ruby on Rails", "backend_runtime", "high"),
        (r"laravel", "Laravel", "backend_runtime", "high"),
        (r"symfony", "Symfony", "backend_runtime", "medium"),
        (r"spring", "Spring", "backend_runtime", "medium"),
        (r"sinatra", "Sinatra", "backend_runtime", "medium"),
        (r"fastify", "Fastify", "backend_runtime", "medium"),
        (r"hapi", "hapi.js", "backend_runtime", "medium"),
        (r"koa", "Koa.js", "backend_runtime", "medium"),
    ],
    "x-generator": [
        (r"wordpress", "WordPress", "cms", "high"),
        (r"drupal", "Drupal", "cms", "high"),
        (r"joomla", "Joomla", "cms", "high"),
        (r"ghost", "Ghost", "cms", "high"),
        (r"hugo", "Hugo", "cms", "high"),
        (r"gatsby", "Gatsby", "frontend_framework", "high"),
        (r"jekyll", "Jekyll", "cms", "high"),
        (r"hexo", "Hexo", "cms", "medium"),
    ],
    "cf-ray": [
        (r".*", "Cloudflare", "cdn", "high"),
    ],
    "x-vercel-id": [
        (r".*", "Vercel", "hosting", "high"),
    ],
    "x-vercel-cache": [
        (r".*", "Vercel", "hosting", "high"),
    ],
    "x-netlify-request-id": [
        (r".*", "Netlify", "hosting", "high"),
    ],
    "x-nf-request-id": [
        (r".*", "Netlify", "hosting", "high"),
    ],
    "x-amz-cf-id": [
        (r".*", "Amazon CloudFront", "cdn", "high"),
    ],
    "x-amz-cf-pop": [
        (r".*", "Amazon CloudFront", "cdn", "high"),
    ],
    "x-cache": [
        (r"cloudfront", "Amazon CloudFront", "cdn", "high"),
        (r"hit from cloudflare", "Cloudflare", "cdn", "high"),
        (r"varnish", "Varnish", "server", "high"),
        (r"fastly", "Fastly", "cdn", "high"),
    ],
    "via": [
        (r"cloudfront", "Amazon CloudFront", "cdn", "medium"),
        (r"varnish", "Varnish", "server", "medium"),
        (r"akamai", "Akamai", "cdn", "high"),
        (r"fastly", "Fastly", "cdn", "high"),
    ],
    "x-akamai-transformed": [
        (r".*", "Akamai", "cdn", "high"),
    ],
    "x-fastly-request-id": [
        (r".*", "Fastly", "cdn", "high"),
    ],
    "x-shopify-stage": [
        (r".*", "Shopify", "ecommerce", "high"),
    ],
    "x-shopify-request-id": [
        (r".*", "Shopify", "ecommerce", "high"),
    ],
    "x-drupal-cache": [
        (r".*", "Drupal", "cms", "high"),
    ],
    "x-drupal-dynamic-cache": [
        (r".*", "Drupal", "cms", "high"),
    ],
    "x-magento-cache-control": [
        (r".*", "Magento", "ecommerce", "high"),
    ],
    "x-wix-request-id": [
        (r".*", "Wix", "cms", "high"),
    ],
    "x-squarespace-did": [
        (r".*", "Squarespace", "cms", "high"),
    ],
    "x-github-request-id": [
        (r".*", "GitHub Pages", "hosting", "high"),
    ],
    "x-firebase-hosting-version": [
        (r".*", "Firebase Hosting", "hosting", "high"),
    ],
    "x-render-origin-server": [
        (r".*", "Render", "hosting", "high"),
    ],
    "fly-request-id": [
        (r".*", "Fly.io", "hosting", "high"),
    ],
    "x-railway-request-id": [
        (r".*", "Railway", "hosting", "high"),
    ],
    "x-azure-ref": [
        (r".*", "Azure", "hosting", "high"),
    ],
    "x-ms-request-id": [
        (r".*", "Azure", "hosting", "medium"),
    ],
    "x-goog-generation": [
        (r".*", "Google Cloud Storage", "hosting", "high"),
    ],
    "x-guploader-uploadid": [
        (r".*", "Google Cloud", "hosting", "high"),
    ],
    "set-cookie": [
        (r"wordpress_logged_in", "WordPress", "cms", "high"),
        (r"wp-settings", "WordPress", "cms", "high"),
        (r"PHPSESSID", "PHP", "backend_runtime", "medium"),
        (r"JSESSIONID", "Java", "backend_runtime", "medium"),
        (r"ASP\.NET_SessionId", "ASP.NET", "backend_runtime", "high"),
        (r"connect\.sid", "Express.js", "backend_runtime", "medium"),
        (r"_shopify", "Shopify", "ecommerce", "high"),
        (r"PrestaShop", "PrestaShop", "ecommerce", "high"),
        (r"AWSALB", "AWS ALB", "hosting", "high"),
        (r"__cf_bm", "Cloudflare", "cdn", "high"),
    ],
}

# HTML-based patterns: (pattern, tech_name, category, confidence, version_group)
HTML_PATTERNS: List[Tuple[str, str, TechCategory, ConfidenceLevel, Optional[int]]] = [
    # Next.js
    (r'<script[^>]*id="__NEXT_DATA__"', "Next.js", "frontend_framework", "high", None),
    (r'_next/static', "Next.js", "frontend_framework", "high", None),
    (r'__NEXT_LOADED_PAGES__', "Next.js", "frontend_framework", "high", None),
    
    # Nuxt.js
    (r'window\.__NUXT__', "Nuxt.js", "frontend_framework", "high", None),
    (r'_nuxt/', "Nuxt.js", "frontend_framework", "high", None),
    (r'nuxt-link', "Nuxt.js", "frontend_framework", "medium", None),
    
    # React
    (r'data-reactroot', "React", "javascript_library", "high", None),
    (r'data-react-helmet', "React", "javascript_library", "medium", None),
    (r'__REACT_DEVTOOLS_GLOBAL_HOOK__', "React", "javascript_library", "medium", None),
    (r'react\.production\.min\.js', "React", "javascript_library", "high", None),
    (r'react-dom', "React", "javascript_library", "medium", None),
    
    # Vue.js
    (r'data-v-[a-f0-9]{8}', "Vue.js", "frontend_framework", "high", None),
    (r'__VUE__', "Vue.js", "frontend_framework", "high", None),
    (r'Vue\s*\.\s*version', "Vue.js", "frontend_framework", "medium", None),
    (r'vue\.runtime\.', "Vue.js", "frontend_framework", "high", None),
    
    # Angular
    (r'ng-version="(\d+\.?\d*\.?\d*)"', "Angular", "frontend_framework", "high", 1),
    (r'ng-app', "AngularJS", "frontend_framework", "high", None),
    (r'angular\.min\.js', "AngularJS", "frontend_framework", "high", None),
    (r'\[ng[A-Z]', "Angular", "frontend_framework", "medium", None),
    
    # Svelte
    (r'__svelte', "Svelte", "frontend_framework", "high", None),
    (r'svelte-[a-z0-9]{6,}', "Svelte", "frontend_framework", "medium", None),
    
    # SvelteKit
    (r'__sveltekit', "SvelteKit", "frontend_framework", "high", None),
    
    # Astro
    (r'astro-island', "Astro", "frontend_framework", "high", None),
    (r'data-astro-cid', "Astro", "frontend_framework", "high", None),
    
    # Gatsby
    (r'___gatsby', "Gatsby", "frontend_framework", "high", None),
    (r'gatsby-', "Gatsby", "frontend_framework", "medium", None),
    
    # Remix
    (r'__remixContext', "Remix", "frontend_framework", "high", None),
    
    # WordPress
    (r'wp-content/', "WordPress", "cms", "high", None),
    (r'wp-includes/', "WordPress", "cms", "high", None),
    (r'wp-json', "WordPress", "cms", "high", None),
    (r'<meta[^>]+generator[^>]+WordPress\s*(\d+\.?\d*\.?\d*)?', "WordPress", "cms", "high", 1),
    
    # Drupal
    (r'Drupal\.settings', "Drupal", "cms", "high", None),
    (r'/sites/default/files', "Drupal", "cms", "high", None),
    (r'<meta[^>]+generator[^>]+Drupal\s*(\d+)?', "Drupal", "cms", "high", 1),
    
    # Joomla
    (r'/media/jui/', "Joomla", "cms", "high", None),
    (r'<meta[^>]+generator[^>]+Joomla', "Joomla", "cms", "high", None),
    
    # Shopify
    (r'cdn\.shopify\.com', "Shopify", "ecommerce", "high", None),
    (r'Shopify\.theme', "Shopify", "ecommerce", "high", None),
    (r'shopify-section', "Shopify", "ecommerce", "high", None),
    
    # Magento
    (r'/static/version\d+/', "Magento", "ecommerce", "medium", None),
    (r'Mage\.Cookies', "Magento", "ecommerce", "high", None),
    (r'mage/cookies', "Magento", "ecommerce", "high", None),
    
    # PrestaShop
    (r'prestashop', "PrestaShop", "ecommerce", "high", None),
    (r'/themes/[^/]+/assets/', "PrestaShop", "ecommerce", "low", None),
    
    # WooCommerce
    (r'woocommerce', "WooCommerce", "ecommerce", "high", None),
    (r'wc-block', "WooCommerce", "ecommerce", "high", None),
    
    # BigCommerce
    (r'bigcommerce', "BigCommerce", "ecommerce", "high", None),
    
    # Ghost CMS
    (r'ghost-url', "Ghost", "cms", "high", None),
    (r'<meta[^>]+generator[^>]+Ghost\s*(\d+\.?\d*\.?\d*)?', "Ghost", "cms", "high", 1),
    
    # Wix
    (r'wixsite\.com', "Wix", "cms", "high", None),
    (r'static\.wixstatic\.com', "Wix", "cms", "high", None),
    
    # Squarespace
    (r'squarespace\.com', "Squarespace", "cms", "high", None),
    (r'sqsp\.com', "Squarespace", "cms", "high", None),
    
    # Webflow
    (r'webflow\.com', "Webflow", "cms", "high", None),
    (r'w-json', "Webflow", "cms", "medium", None),
    
    # Hugo
    (r'<meta[^>]+generator[^>]+Hugo', "Hugo", "cms", "high", None),
    
    # Jekyll
    (r'<meta[^>]+generator[^>]+Jekyll', "Jekyll", "cms", "high", None),
    
    # Eleventy
    (r'<meta[^>]+generator[^>]+Eleventy', "Eleventy", "cms", "high", None),
    
    # Analytics & Tag Managers
    (r'googletagmanager\.com', "Google Tag Manager", "tag_manager", "high", None),
    (r'gtag\(', "Google Analytics (gtag)", "analytics", "high", None),
    (r'google-analytics\.com/ga\.js', "Google Analytics (legacy)", "analytics", "high", None),
    (r'google-analytics\.com/analytics\.js', "Google Analytics (Universal)", "analytics", "high", None),
    (r'www\.googletagmanager\.com/gtm\.js', "Google Tag Manager", "tag_manager", "high", None),
    (r'segment\.com', "Segment", "analytics", "high", None),
    (r'analytics\.js', "Segment", "analytics", "low", None),
    (r'hotjar\.com', "Hotjar", "analytics", "high", None),
    (r'static\.hotjar\.com', "Hotjar", "analytics", "high", None),
    (r'cdn\.amplitude\.com', "Amplitude", "analytics", "high", None),
    (r'cdn\.mxpnl\.com', "Mixpanel", "analytics", "high", None),
    (r'plausible\.io', "Plausible", "analytics", "high", None),
    (r'umami\.is', "Umami", "analytics", "high", None),
    (r'fathom\.com', "Fathom", "analytics", "high", None),
    (r'heap-analytics', "Heap", "analytics", "high", None),
    (r'fullstory\.com', "FullStory", "analytics", "high", None),
    (r'clarity\.ms', "Microsoft Clarity", "analytics", "high", None),
    (r'posthog\.com', "PostHog", "analytics", "high", None),
    
    # JavaScript Libraries
    (r'jquery\.min\.js', "jQuery", "javascript_library", "high", None),
    (r'jquery-(\d+\.?\d*\.?\d*)', "jQuery", "javascript_library", "high", 1),
    (r'lodash', "Lodash", "javascript_library", "medium", None),
    (r'moment\.js', "Moment.js", "javascript_library", "medium", None),
    (r'axios', "Axios", "javascript_library", "low", None),
    (r'alpinejs', "Alpine.js", "javascript_library", "high", None),
    (r'x-data=', "Alpine.js", "javascript_library", "high", None),
    (r'htmx\.org', "htmx", "javascript_library", "high", None),
    (r'hx-get|hx-post', "htmx", "javascript_library", "high", None),
    
    # Build Tools / Bundlers
    (r'webpack', "Webpack", "build_tool", "low", None),
    (r'parcel', "Parcel", "build_tool", "low", None),
    (r'vite', "Vite", "build_tool", "low", None),
    
    # API Styles (inferred)
    (r'/graphql', "GraphQL", "api_style", "high", None),
    (r'__typename', "GraphQL", "api_style", "high", None),
    (r'/api/trpc', "tRPC", "api_style", "high", None),
    (r'trpcState', "tRPC", "api_style", "high", None),
    
    # Frameworks (backend hints in HTML)
    (r'csrfmiddlewaretoken', "Django", "backend_runtime", "high", None),
    (r'csrf_token', "Flask/Django", "backend_runtime", "low", None),
    (r'authenticity_token', "Ruby on Rails", "backend_runtime", "high", None),
    (r'laravel_token', "Laravel", "backend_runtime", "high", None),
    (r'_token\s*:\s*[\'"]', "Laravel", "backend_runtime", "medium", None),
]

# URL path patterns for 404 probes
PATH_PROBE_SIGNATURES: Dict[str, Tuple[str, TechCategory, ConfidenceLevel]] = {
    # Path probe patterns: pattern_in_response -> (tech_name, category, confidence)
    "The page you're looking for doesn't exist": ("Ruby on Rails", "backend_runtime", "medium"),
    "Page not found - Django": ("Django", "backend_runtime", "high"),
    "Express": ("Express.js", "backend_runtime", "low"),
    "Symfony Component": ("Symfony", "backend_runtime", "high"),
    "SQLSTATE": ("PHP + SQL Database", "backend_runtime", "medium"),
    "ASP.NET": ("ASP.NET", "backend_runtime", "high"),
    "This page does not exist": ("Next.js", "frontend_framework", "low"),
    "NOT_FOUND": ("Next.js", "frontend_framework", "low"),
    "undefined | Gatsby": ("Gatsby", "frontend_framework", "medium"),
}


# =============================================================================
# WAPPALYZER INTEGRATION
# =============================================================================

def _try_import_wappalyzer():
    """Try to import Wappalyzer. Returns (Wappalyzer, WebPage) or (None, None)."""
    try:
        from Wappalyzer import Wappalyzer, WebPage
        return Wappalyzer, WebPage
    except ImportError:
        return None, None


def _wappalyzer_detect(
    url: str, 
    html: str, 
    headers: Dict[str, str]
) -> List[TechDetection]:
    """
    Attempt detection using Wappalyzer library.
    Returns empty list if Wappalyzer is not available.
    """
    Wappalyzer, WebPage = _try_import_wappalyzer()
    
    if Wappalyzer is None:
        return []
    
    detections: List[TechDetection] = []
    
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage(url, html, headers)
        results = wappalyzer.analyze(webpage)
        
        for tech_name in results:
            # Map Wappalyzer categories to our categories
            category = _map_wappalyzer_category(tech_name, results.get(tech_name, {}))
            
            detections.append(TechDetection(
                name=tech_name,
                category=category,
                confidence="medium",  # Wappalyzer doesn't provide confidence
                evidence=[f"wappalyzer: {tech_name} detected"],
                source="wappalyzer"
            ))
            
    except Exception as e:
        logger.warning(f"Wappalyzer detection failed: {e}")
    
    return detections


def _map_wappalyzer_category(tech_name: str, tech_info: dict) -> TechCategory:
    """Map Wappalyzer technology to our category system."""
    name_lower = tech_name.lower()
    
    # Common mappings based on name
    category_keywords = {
        "frontend_framework": ["react", "vue", "angular", "svelte", "next", "nuxt", "gatsby", "remix", "astro"],
        "backend_runtime": ["node", "express", "django", "flask", "rails", "laravel", "spring", "php", "asp.net"],
        "cms": ["wordpress", "drupal", "joomla", "ghost", "strapi", "contentful", "sanity"],
        "ecommerce": ["shopify", "magento", "woocommerce", "prestashop", "bigcommerce"],
        "server": ["nginx", "apache", "iis", "caddy", "tomcat"],
        "cdn": ["cloudflare", "fastly", "akamai", "cloudfront"],
        "hosting": ["vercel", "netlify", "heroku", "aws", "azure", "gcp"],
        "analytics": ["google analytics", "segment", "mixpanel", "amplitude", "hotjar"],
        "javascript_library": ["jquery", "lodash", "moment", "axios"],
    }
    
    for category, keywords in category_keywords.items():
        if any(kw in name_lower for kw in keywords):
            return category  # type: ignore
    
    return "unknown"


# =============================================================================
# HEURISTIC DETECTION ENGINE
# =============================================================================

def _detect_from_headers(headers: Dict[str, str]) -> List[TechDetection]:
    """Detect technologies from HTTP response headers."""
    detections: List[TechDetection] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for header_name, patterns in HEADER_PATTERNS.items():
        header_value = headers_lower.get(header_name, "")
        if not header_value:
            continue
            
        for pattern, tech_name, category, confidence in patterns:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                version = None
                # Try to extract version from named groups or first group
                if match.groups():
                    version = match.group(1) if len(match.groups()) >= 1 else None
                    
                evidence = f"header: {header_name}={header_value[:100]}"
                
                detections.append(TechDetection(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    evidence=[evidence],
                    version=version,
                    source="heuristic"
                ))
    
    return detections


def _detect_from_html(html: str) -> List[TechDetection]:
    """Detect technologies from HTML content."""
    detections: List[TechDetection] = []
    
    if not html:
        return detections
    
    for pattern, tech_name, category, confidence, version_group in HTML_PATTERNS:
        try:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = None
                if version_group and len(match.groups()) >= version_group:
                    version = match.group(version_group)
                
                # Create a snippet for evidence (max 200 chars around match)
                start = max(0, match.start() - 50)
                end = min(len(html), match.end() + 50)
                snippet = html[start:end].replace('\n', ' ').strip()
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                
                evidence = f"html_marker: {pattern[:50]}... matched: '{snippet}'"
                
                detections.append(TechDetection(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    evidence=[evidence],
                    version=version,
                    source="heuristic"
                ))
        except re.error as e:
            logger.warning(f"Regex error for pattern {pattern}: {e}")
            continue
    
    return detections


def _detect_from_404(body: str, status_code: int) -> List[TechDetection]:
    """Detect technologies from 404 error page response."""
    detections: List[TechDetection] = []
    
    if not body:
        return detections
    
    for signature, (tech_name, category, confidence) in PATH_PROBE_SIGNATURES.items():
        if signature.lower() in body.lower():
            detections.append(TechDetection(
                name=tech_name,
                category=category,
                confidence=confidence,
                evidence=[f"404_probe: signature '{signature}' found in error page"],
                source="heuristic"
            ))
    
    return detections


def _redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact sensitive header values while keeping useful info."""
    sensitive_patterns = ["authorization", "cookie", "api-key", "token", "secret"]
    redacted = {}
    
    for key, value in headers.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in sensitive_patterns):
            redacted[key] = "[REDACTED]"
        elif len(value) > 200:
            redacted[key] = value[:200] + "...[TRUNCATED]"
        else:
            redacted[key] = value
    
    return redacted


# =============================================================================
# MAIN FINGERPRINTER CLASS
# =============================================================================

class TechFingerprinter:
    """
    Tech Fingerprinting orchestrator.
    
    Combines Wappalyzer (optional) with heuristic detection.
    Uses the existing HTTP client from the scan engine.
    """
    
    def __init__(
        self, 
        http_client,  # HttpClient from engine
        log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
        max_probes: int = 5,
        timeout: float = 10.0
    ):
        """
        Initialize fingerprinter.
        
        Args:
            http_client: Async HTTP client from scan engine
            log_callback: Optional async logging callback (level, message)
            max_probes: Maximum additional HTTP probes (including 404 probe)
            timeout: Request timeout in seconds
        """
        self.http_client = http_client
        self.log = log_callback
        self.max_probes = max_probes
        self.timeout = timeout
        self.probe_count = 0
    
    async def _log(self, level: str, message: str):
        """Log a message if callback is available."""
        if self.log:
            await self.log(level, message)
    
    async def fingerprint(
        self,
        url: str,
        response_html: str,
        response_headers: Dict[str, str],
        status_code: int = 200,
        perform_404_probe: bool = True
    ) -> TechFingerprintResult:
        """
        Perform tech fingerprinting on target.
        
        Args:
            url: Target URL
            response_html: HTML content from initial request
            response_headers: HTTP headers from initial request
            status_code: HTTP status code from initial request
            perform_404_probe: Whether to perform a controlled 404 probe
            
        Returns:
            TechFingerprintResult with all detected technologies
        """
        result = TechFingerprintResult()
        methods_used: List[str] = []
        
        await self._log("INFO", f"Starting tech fingerprinting for {url}")
        
        # Check if we're blocked
        if status_code in [403, 401, 429, 503]:
            result.blocked_by_waf = True
            result.probe_failures.append(f"Initial request returned {status_code}")
            await self._log("WARNING", f"Tech fingerprinting limited: status {status_code}")
        
        # 1. Header-based detection (always)
        await self._log("INFO", "Analyzing HTTP headers...")
        header_detections = _detect_from_headers(response_headers)
        for det in header_detections:
            result.merge_detection(det)
        methods_used.append("header_analysis")
        
        # 2. HTML-based detection (if HTML available)
        if response_html and "text/html" in response_headers.get("content-type", "").lower():
            await self._log("INFO", "Analyzing HTML content...")
            html_detections = _detect_from_html(response_html)
            for det in html_detections:
                result.merge_detection(det)
            methods_used.append("html_analysis")
        
        # 3. Wappalyzer detection (optional)
        await self._log("INFO", "Attempting Wappalyzer detection...")
        wap_detections = _wappalyzer_detect(url, response_html, response_headers)
        if wap_detections:
            for det in wap_detections:
                result.merge_detection(det)
            methods_used.append("wappalyzer")
            await self._log("INFO", f"Wappalyzer detected {len(wap_detections)} technologies")
        else:
            await self._log("INFO", "Wappalyzer not available, using heuristics only")
            methods_used.append("wappalyzer_unavailable")
        
        # 4. Controlled 404 probe (optional, safe)
        if perform_404_probe and self.probe_count < self.max_probes and not result.blocked_by_waf:
            await self._log("INFO", "Performing controlled 404 probe...")
            try:
                probe_detections = await self._perform_404_probe(url)
                for det in probe_detections:
                    result.merge_detection(det)
                methods_used.append("404_probe")
            except Exception as e:
                result.probe_failures.append(f"404 probe failed: {str(e)}")
                await self._log("WARNING", f"404 probe failed: {e}")
        
        # Store metadata
        result.detection_methods = methods_used
        result.probe_count = self.probe_count
        result.raw_headers_sample = _redact_sensitive_headers(response_headers)
        
        # Summary log
        tech_count = len(result.technologies)
        categories = set(t.category for t in result.technologies)
        await self._log(
            "INFO", 
            f"Tech fingerprinting complete: {tech_count} technologies in {len(categories)} categories"
        )
        
        return result
    
    async def _perform_404_probe(self, base_url: str) -> List[TechDetection]:
        """
        Perform a single controlled 404 probe to detect framework signatures.
        Uses a randomized path to avoid caching.
        """
        import uuid
        
        detections: List[TechDetection] = []
        
        # Generate unique 404 path
        probe_path = f"/relic-probe-{uuid.uuid4().hex[:8]}-not-exist"
        
        parsed = urlparse(base_url)
        probe_url = f"{parsed.scheme}://{parsed.netloc}{probe_path}"
        
        self.probe_count += 1
        
        try:
            response = await self.http_client.get(probe_url)
            body = response.text if hasattr(response, 'text') else str(response.content)
            status = response.status_code
            
            # Analyze 404 response
            detections = _detect_from_404(body, status)
            
            # Also check 404 page HTML for tech markers
            if body:
                html_detections = _detect_from_html(body)
                for det in html_detections:
                    det.evidence.append("detected in 404 error page")
                    detections.append(det)
                    
        except Exception as e:
            logger.warning(f"404 probe request failed: {e}")
            raise
        
        return detections


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

async def detect_technologies(
    url: str,
    html: str,
    headers: Dict[str, str],
    http_client=None,
    log_callback=None,
    status_code: int = 200,
    perform_404_probe: bool = True
) -> TechFingerprintResult:
    """
    Convenience function for tech detection.
    
    Can be called without full HTTP client if only analyzing 
    existing response data (no 404 probe).
    
    Args:
        url: Target URL
        html: HTML content
        headers: HTTP response headers
        http_client: Optional HTTP client for additional probes
        log_callback: Optional async logging callback
        status_code: Response status code
        perform_404_probe: Whether to probe 404 (requires http_client)
        
    Returns:
        TechFingerprintResult
    """
    if http_client:
        fp = TechFingerprinter(
            http_client=http_client,
            log_callback=log_callback
        )
        return await fp.fingerprint(
            url=url,
            response_html=html,
            response_headers=headers,
            status_code=status_code,
            perform_404_probe=perform_404_probe
        )
    else:
        # No HTTP client - just analyze provided data
        result = TechFingerprintResult()
        
        # Header detection
        for det in _detect_from_headers(headers):
            result.merge_detection(det)
        result.detection_methods.append("header_analysis")
        
        # HTML detection
        if html:
            for det in _detect_from_html(html):
                result.merge_detection(det)
            result.detection_methods.append("html_analysis")
        
        # Wappalyzer
        wap_detections = _wappalyzer_detect(url, html, headers)
        for det in wap_detections:
            result.merge_detection(det)
        if wap_detections:
            result.detection_methods.append("wappalyzer")
        
        result.raw_headers_sample = _redact_sensitive_headers(headers)
        
        return result
