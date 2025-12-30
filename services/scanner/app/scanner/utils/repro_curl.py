"""
Helper utilities for generating reproducible cURL commands.
"""
from typing import Dict, Optional
import urllib.parse

# Headers that are safe to include in repro commands
SAFE_HEADERS = frozenset([
    "origin",
    "content-type", 
    "accept",
    "user-agent",
])

# Fixed User-Agent for reproducibility
RELIC_USER_AGENT = "RelicScanner/1.0"


def build_repro_curl(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None
) -> str:
    """
    Builds a safe, reproducible cURL command.
    
    Security rules:
    - NEVER includes Cookie, Authorization, API keys, Bearer tokens
    - Header whitelist: Origin, Content-Type, Accept, User-Agent
    - User-Agent is fixed to "RelicScanner/1.0"
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: The target URL
        headers: Optional dict of headers (will be filtered)
        data: Optional request body for POST/PUT
        
    Returns:
        A safe cURL command string
    """
    parts = ["curl"]
    
    # Method
    method_upper = method.upper()
    if method_upper != "GET":
        parts.append(f"-X {method_upper}")
    
    # Always add our fixed User-Agent
    parts.append(f"-H 'User-Agent: {RELIC_USER_AGENT}'")
    
    # Filter and add safe headers
    if headers:
        for key, value in headers.items():
            key_lower = key.lower()
            # Skip forbidden headers
            if key_lower in ("cookie", "authorization", "x-api-key", "api-key"):
                continue
            # Skip bearer tokens in any header
            if "bearer" in str(value).lower():
                continue
            # Only include whitelisted headers
            if key_lower in SAFE_HEADERS and key_lower != "user-agent":
                # Escape single quotes in value
                safe_value = str(value).replace("'", "\\'")
                parts.append(f"-H '{key}: {safe_value}'")
    
    # Add data if present (for POST/PUT)
    if data and method_upper in ("POST", "PUT", "PATCH"):
        # Escape single quotes in data
        safe_data = data.replace("'", "\\'")
        parts.append(f"-d '{safe_data}'")
    
    # Add the URL (escape single quotes)
    safe_url = url.replace("'", "%27")
    parts.append(f"'{safe_url}'")
    
    return " ".join(parts)


def build_xss_repro_curl(base_url: str, param: str, payload: str) -> str:
    """
    Builds a cURL command for reproducing an XSS finding.
    
    Args:
        base_url: The base URL without query params
        param: The vulnerable parameter name
        payload: The XSS payload that triggered the vulnerability
        
    Returns:
        A cURL command string
    """
    # URL-encode the payload
    encoded_payload = urllib.parse.quote(payload, safe='')
    test_url = f"{base_url}?{param}={encoded_payload}"
    
    return build_repro_curl("GET", test_url)


def build_sqli_repro_curl(base_url: str, param: str, payload: str) -> str:
    """
    Builds a cURL command for reproducing a SQLi finding.
    
    Args:
        base_url: The base URL without query params
        param: The vulnerable parameter name
        payload: The SQLi payload that triggered the vulnerability
        
    Returns:
        A cURL command string
    """
    # URL-encode the payload
    encoded_payload = urllib.parse.quote(payload, safe='')
    test_url = f"{base_url}?{param}={encoded_payload}"
    
    return build_repro_curl("GET", test_url)


def build_cors_repro_curl(target_url: str, origin: str) -> str:
    """
    Builds a cURL command for reproducing a CORS finding.
    
    Args:
        target_url: The target URL
        origin: The malicious origin that was reflected
        
    Returns:
        A cURL command string with Origin header
    """
    return build_repro_curl("GET", target_url, headers={"Origin": origin})


def build_sensitive_file_repro_curl(url: str) -> str:
    """
    Builds a cURL command for reproducing a sensitive file exposure.
    
    Args:
        url: The URL where sensitive file was found
        
    Returns:
        A simple GET cURL command
    """
    return build_repro_curl("GET", url)
