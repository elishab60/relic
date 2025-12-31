import asyncio
from enum import Enum
from typing import List, Dict, Any, Callable, Awaitable, Set
from urllib.parse import urljoin
from .http_client import HttpClient


class PathDiscoveryProfile(Enum):
    """
    Discovery profiles that control the depth and breadth of path discovery.
    
    - MINIMAL: ~10-15 paths (very fast, legacy behavior)
    - STANDARD: ~40-60 paths (default, balanced coverage)
    - THOROUGH: ~80-120 paths (higher coverage, bounded)
    """
    MINIMAL = "minimal"
    STANDARD = "standard"
    THOROUGH = "thorough"


# =============================================================================
# PATH DEFINITIONS BY PROFILE
# =============================================================================

# MINIMAL profile paths (~13 paths) - matches original behavior
PATHS_MINIMAL: List[str] = [
    # Core sensitive paths
    "/admin",
    "/login",
    "/auth",
    "/dashboard",
    "/api",
    "/config",
    "/backup",
    "/backup.zip",
    "/phpinfo.php",
    "/.env",
    "/.git/HEAD",
    "/robots.txt",
    "/sitemap.xml",
]

# Additional paths for STANDARD profile (~35 more paths, total ~48)
PATHS_STANDARD_ADDITIONS: List[str] = [
    # Debug & diagnostics
    "/debug",
    "/_debug",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/info",
    "/server-status",
    "/server-info",
    "/status",
    "/health",
    "/healthcheck",
    
    # Admin & consoles
    "/console",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/phpmyadmin",
    "/adminer",
    
    # APIs & schemas
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger.json",
    "/swagger-ui.html",
    "/v3/api-docs",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    
    # CI / Dev artifacts
    "/.git",
    "/.git/config",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/config.yml",
    "/settings.json",
    
    # Common metadata
    "/favicon.ico",
    "/crossdomain.xml",
    "/security.txt",
    "/.well-known/security.txt",
]

# Additional paths for THOROUGH profile (~50 more paths, total ~98)
PATHS_THOROUGH_ADDITIONS: List[str] = [
    # Extended debug & diagnostics
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/threaddump",
    "/actuator/heapdump",
    "/trace",
    "/debug/vars",
    "/debug/pprof",
    "/elmah.axd",
    "/info",
    "/__debug__",
    
    # Extended admin & consoles
    "/cpanel",
    "/webmail",
    "/plesk",
    "/manager/html",
    "/jmx-console",
    "/web-console",
    "/admin.php",
    "/admin.html",
    "/backend",
    "/manage",
    "/controlpanel",
    
    # Extended APIs
    "/api/swagger.json",
    "/api/docs",
    "/api/schema",
    "/docs",
    "/redoc",
    "/api-docs",
    "/api/graphql",
    "/api/rest",
    
    # Extended dev artifacts
    "/.gitignore",
    "/.htaccess",
    "/.htpasswd",
    "/composer.json",
    "/composer.lock",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    
    # Backups & archives
    "/backup.sql",
    "/backup.tar.gz",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/site.zip",
    "/www.zip",
    "/data.zip",
    
    # CMS-specific paths
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-includes",
    "/wp-content",
    "/xmlrpc.php",
    
    # Error pages & logs
    "/error.log",
    "/errors.log",
    "/access.log",
    "/debug.log",
    "/app.log",
    
    # Additional metadata
    "/humans.txt",
    "/ads.txt",
    "/app-ads.txt",
]


def get_paths_for_profile(profile: PathDiscoveryProfile) -> List[str]:
    """
    Returns a deduplicated, ordered list of paths for the given profile.
    
    Profiles are cumulative:
    - MINIMAL includes only PATHS_MINIMAL
    - STANDARD includes MINIMAL + STANDARD_ADDITIONS
    - THOROUGH includes STANDARD + THOROUGH_ADDITIONS
    """
    paths: List[str] = []
    seen: Set[str] = set()
    
    def add_paths(path_list: List[str]) -> None:
        for path in path_list:
            if path not in seen:
                seen.add(path)
                paths.append(path)
    
    # Always include MINIMAL paths
    add_paths(PATHS_MINIMAL)
    
    if profile in (PathDiscoveryProfile.STANDARD, PathDiscoveryProfile.THOROUGH):
        add_paths(PATHS_STANDARD_ADDITIONS)
    
    if profile == PathDiscoveryProfile.THOROUGH:
        add_paths(PATHS_THOROUGH_ADDITIONS)
    
    return paths


# =============================================================================
# CRAWL URL LIMITS BY PROFILE
# =============================================================================

# Crawl limits control how many URLs the streaming crawler follows from HTML links
CRAWL_LIMITS = {
    PathDiscoveryProfile.MINIMAL: 20,    # Fast scan, fewer pages
    PathDiscoveryProfile.STANDARD: 50,   # Balanced coverage
    PathDiscoveryProfile.THOROUGH: 100,  # Deep crawl, more pages
}


def get_crawl_limit_for_profile(profile: PathDiscoveryProfile) -> int:
    """Returns the max crawl URLs limit for the given profile."""
    return CRAWL_LIMITS.get(profile, CRAWL_LIMITS[PathDiscoveryProfile.STANDARD])


class PathDiscoverer:
    """
    Performs dictionary-based path discovery to find sensitive endpoints.
    
    Supports discovery profiles to control scan depth:
    - MINIMAL: ~13 paths (fast, legacy behavior)
    - STANDARD: ~48 paths (default, balanced)
    - THOROUGH: ~98 paths (deep scan, bounded)
    """
    
    # Paths that are considered "sensitive" if found
    SENSITIVE_MARKERS: Set[str] = {
        # Original sensitive markers
        "/admin", "/.env", "/.git/HEAD", "/backup.zip", "/phpinfo.php", "/config",
        # Extended sensitive markers
        "/.git", "/.git/config", "/.env.local", "/.env.production",
        "/config.json", "/config.yml", "/settings.json",
        "/actuator/env", "/actuator/heapdump", "/actuator/configprops",
        "/wp-config.php", "/wp-config.php.bak",
        "/.htpasswd", "/dump.sql", "/database.sql", "/db.sql", "/backup.sql",
        "/backup.tar.gz", "/site.zip", "/www.zip", "/data.zip",
        "/composer.json", "/package.json", "/requirements.txt",
        "/error.log", "/errors.log", "/access.log", "/debug.log", "/app.log",
        "/debug", "/_debug", "/__debug__", "/debug/vars", "/debug/pprof",
        "/elmah.axd", "/jmx-console", "/web-console", "/manager/html",
    }

    # Login path patterns to detect redirects
    LOGIN_PATTERNS: List[str] = [
        "/login",
        "/signin",
        "/sign-in",
        "/auth/login",
        "/auth/signin",
        "/account/login",
        "/user/login",
        "/wp-login.php",
    ]

    def __init__(
        self, 
        http_client: HttpClient, 
        log_callback: Callable[[str, str], Awaitable[None]] = None,
        profile: PathDiscoveryProfile = PathDiscoveryProfile.STANDARD
    ):
        """
        Initialize PathDiscoverer.
        
        Args:
            http_client: HTTP client for making requests
            log_callback: Optional async callback for logging
            profile: Discovery profile (default: STANDARD)
        """
        self.http_client = http_client
        self.log_callback = log_callback
        self.profile = profile
        self._paths_to_check = get_paths_for_profile(profile)

    @property
    def paths_to_check(self) -> List[str]:
        """Returns the list of paths to check for this instance."""
        return self._paths_to_check

    async def run(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Probes the base_url for common paths.
        """
        if self.log_callback:
            await self.log_callback("INFO", "Starting path discovery...")
            
        discovered_paths = []
        
        # Ensure base_url doesn't end with slash for cleaner joins if paths start with slash
        # But urljoin handles it well.
        
        tasks = []
        for path in self._paths_to_check:
            tasks.append(self._check_path(base_url, path))
            
        # Run concurrently
        results = await asyncio.gather(*tasks)
        
        # Filter out None results (if any) and add to list
        interesting_count = 0
        for res in results:
            if res:
                discovered_paths.append(res)
                if res.get("sensitive"):
                    interesting_count += 1
        
        if self.log_callback:
            await self.log_callback("INFO", f"Path discovery completed. Found {interesting_count} interesting endpoints.")
            
        return discovered_paths

    async def _check_path(self, base_url: str, path: str) -> Dict[str, Any]:
        full_url = urljoin(base_url, path)
        
        try:
            # Use GET to follow redirects and see final URL
            response = await self.http_client.get(full_url)
            
            if response:
                status = response.status_code
                
                # We are interested in 200, 301, 302, 401, 403
                if status in [200, 301, 302, 401, 403]:
                    is_sensitive_pattern = path in self.SENSITIVE_MARKERS
                    
                    # Analyze for login redirect
                    final_url = str(response.url)
                    final_path = final_url.replace(response.url.scheme + "://" + response.url.netloc, "")
                    
                    # Check if final URL matches login patterns
                    is_login_redirect = False
                    for login_pat in self.LOGIN_PATTERNS:
                        if login_pat in final_path.lower():
                            is_login_redirect = True
                            break
                    
                    # Determine classification
                    access_control = "unknown"
                    sensitive = False
                    reason = ""
                    
                    if is_sensitive_pattern:
                        if is_login_redirect:
                            sensitive = False
                            access_control = "login_redirect"
                            reason = "Endpoint appears protected by authentication (redirect to login)."
                        elif status in [401, 403]:
                            sensitive = False # It's protected, so not "exposed" in a dangerous way (though existence is known)
                            access_control = "restricted"
                            reason = f"Endpoint exists but is restricted ({status})."
                        else:
                            # Direct access (200) or other redirect not to login
                            sensitive = True
                            access_control = "direct"
                            reason = f"Potentially sensitive endpoint exposed: {path}"
                    else:
                        # Non-sensitive path (e.g. robots.txt)
                        sensitive = False
                        access_control = "direct" if status == 200 else "unknown"
                        reason = f"Discovered path: {path}"

                    result = {
                        "url": full_url,
                        "status_code": status,
                        "content_type": response.headers.get("Content-Type", ""),
                        "sensitive": sensitive,
                        "access_control": access_control,
                        "reason": reason,
                        "final_url": final_url
                    }
                        
                    return result
                    
        except Exception:
            pass
            
        return None
