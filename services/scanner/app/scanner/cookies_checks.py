from typing import List, Dict, Any
from httpx import Response
from http.cookies import SimpleCookie
from .models import Finding
from ..constants import Severity, Category

def analyze_cookies(history: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], Dict[str, Any], List[Finding]]:
    """
    Analyzes cookies from the HTTP history (Set-Cookie headers).
    Returns:
        - List of cookie details (for debug_info['cookies'])
        - Summary dict (for debug_info['cookies_summary'])
        - List of findings
    """
    seen_cookies = {} 
    processed_cookies = []
    findings = []
    
    # Heuristics
    SESSION_KEYWORDS = ["session", "sid", "auth", "token", "jwt", "login", "sso"]
    
    for entry in history:
        # History entries are dicts with "response_headers"
        headers = entry.get("response_headers", {})
        
        # Look for Set-Cookie (case-insensitive search in dict keys)
        # Since it's a dict, we might only get one value if multiple headers existed.
        cookie_header = None
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                cookie_header = v
                break
        
        if not cookie_header:
            continue
            
        # cookie_header is a string (or list if we changed HttpClient, but currently string)
        # If multiple Set-Cookie headers were present, HttpClient (dict conversion) likely kept only the last one.
        # We process what we have.
        
        # SimpleCookie.load() can handle "name=value; Path=/..."
        # It can also handle multiple cookies separated by specific delimiters if passed correctly, 
        # but Set-Cookie values are usually distinct headers. 
        # If we have a single string, we treat it as one Set-Cookie line.
        
        try:
            parser = SimpleCookie()
            parser.load(cookie_header)
            
            for name, morsel in parser.items():
                # Parse attributes
                # morsel keys: key, value, coded_value, legal_chars, id, ...
                # attributes are in morsel keys like 'path', 'domain', 'secure', 'httponly', 'samesite', 'expires', 'max-age'
                
                # Note: SimpleCookie keys are lowercase in the internal dict (morsel), e.g. morsel['secure']
                
                # Domain fallback: use the host from the URL in the history entry
                # entry["url"] might be the requested URL. entry["final_url"] is better.
                host = "unknown"
                if "final_url" in entry:
                    from urllib.parse import urlparse
                    host = urlparse(entry["final_url"]).hostname
                
                cookie_obj = {
                    "name": name,
                    "value": morsel.value[:50] + "..." if len(morsel.value) > 50 else morsel.value, # Truncate
                    "domain": morsel['domain'] or host, 
                    "path": morsel['path'] or "/",
                    "secure": bool(morsel['secure']),
                    "httponly": bool(morsel['httponly']),
                    "samesite": morsel['samesite'] if morsel['samesite'] else None,
                    "expires": morsel['expires'] if morsel['expires'] else None
                }
                    
                # Classification
                lower_name = name.lower()
                if any(k in lower_name for k in SESSION_KEYWORDS):
                    cookie_obj["type"] = "session_guess"
                else:
                    cookie_obj["type"] = "generic"
                    
                # Deduplication key
                key = (cookie_obj["name"], cookie_obj["domain"], cookie_obj["path"])
                
                # We might want to update if it exists, or just append?
                # Let's append if not seen, to capture distinct cookies.
                # If we see the same cookie updated, maybe we want the latest state?
                # Let's just keep unique keys.
                
                found = False
                for i, existing in enumerate(processed_cookies):
                    if (existing["name"], existing["domain"], existing["path"]) == key:
                        processed_cookies[i] = cookie_obj # Update with latest
                        found = True
                        break
                if not found:
                    processed_cookies.append(cookie_obj)
                        
        except Exception:
            # Failed to parse a cookie header
            continue

    # Analysis & Findings
    issues_list = []
    session_like_count = 0
    
    for cookie in processed_cookies:
        name = cookie["name"]
        is_session = cookie["type"] == "session_guess"
        if is_session:
            session_like_count += 1
            
        # Security Checks
        
        # 1. Secure flag
        # We assume the site is HTTPS if the cookie was set over HTTPS or if the site is intended to be HTTPS.
        # But we don't strictly know if the *site* is HTTPS here without context.
        # However, if the cookie is "Secure", it's fine. If not, and it's a session cookie, it's bad.
        # But if the site is HTTP, Secure flag would break it.
        # Requirement: "Is Secure set when site uses HTTPS?"
        # We can check if the response where it was set was HTTPS? 
        # But we iterated history. Let's assume we want Secure on session cookies regardless, 
        # or we only flag if we know we are on HTTPS.
        # Let's be strict for session cookies: should be Secure.
        # But wait, if I test http://localhost, Secure is bad.
        # Let's check if the cookie has 'secure' flag.
        
        if not cookie["secure"]:
            # If it's a session cookie, this is a medium issue
            if is_session:
                issues_list.append(f"Cookie '{name}' (session) is missing 'Secure' flag.")
                findings.append(Finding(
                    title=f"Insecure Session Cookie: {name}",
                    severity=Severity.MEDIUM,
                    category=Category.COOKIES,
                    description=f"The session cookie '{name}' does not have the 'Secure' flag set.",
                    recommendation=f"Set the 'Secure' flag for '{name}' to prevent transmission over unencrypted connections.",
                    evidence=f"Cookie: {name}"
                ))
            else:
                # Generic cookie missing secure - maybe info/low
                pass

        # 2. HttpOnly
        if not cookie["httponly"]:
            if is_session:
                issues_list.append(f"Cookie '{name}' (session) is missing 'HttpOnly' flag.")
                findings.append(Finding(
                    title=f"Session Cookie Missing HttpOnly: {name}",
                    severity=Severity.MEDIUM,
                    category=Category.COOKIES,
                    description=f"The session cookie '{name}' does not have the 'HttpOnly' flag set, making it accessible to JavaScript.",
                    recommendation=f"Set the 'HttpOnly' flag for '{name}' to prevent XSS attacks from stealing the session.",
                    evidence=f"Cookie: {name}"
                ))
        
        # 3. SameSite
        if not cookie["samesite"]:
            issues_list.append(f"Cookie '{name}' has no SameSite attribute.")
            findings.append(Finding(
                title=f"Cookie Missing SameSite: {name}",
                severity=Severity.LOW,
                category=Category.COOKIES,
                description=f"The cookie '{name}' does not have the 'SameSite' attribute set.",
                recommendation=f"Set 'SameSite' to 'Lax' or 'Strict' for '{name}' to protect against CSRF.",
                evidence=f"Cookie: {name}"
            ))
            
    summary = {
        "count": len(processed_cookies),
        "session_like_count": session_like_count,
        "issues": issues_list
    }
    
    if not processed_cookies:
        summary["notes"] = ["No Set-Cookie headers found"]
        
    return processed_cookies, summary, findings
