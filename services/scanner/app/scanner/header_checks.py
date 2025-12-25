from typing import List, Dict
from .models import Finding
from ..constants import Severity, Category

def check_security_headers(headers: Dict[str, str]) -> List[Finding]:
    """
    Checks for missing or misconfigured security headers.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    # Strict-Transport-Security
    if "strict-transport-security" not in headers_lower:
        findings.append(Finding(
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            category=Category.HEADERS,
            description="The 'Strict-Transport-Security' header is missing. This header ensures that browsers only connect to the site via HTTPS.",
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
        
    # Content-Security-Policy
    if "content-security-policy" not in headers_lower:
        findings.append(Finding(
            title="Missing Content-Security-Policy",
            severity=Severity.MEDIUM,
            category=Category.HEADERS,
            description="The 'Content-Security-Policy' header is missing. This header helps prevent XSS and other code injection attacks.",
            recommendation="Define a strict Content-Security-Policy to restrict sources of executable scripts and other resources.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
    else:
        csp_value = headers_lower["content-security-policy"]
        if "'unsafe-eval'" in csp_value:
            findings.append(Finding(
                title="CSP permissive (unsafe-eval)",
                severity=Severity.INFO,
                category=Category.HEADERS,
                description="The Content-Security-Policy allows 'unsafe-eval', which enables the use of eval() and similar mechanisms.",
                recommendation="Avoid using 'unsafe-eval' if possible.",
                evidence=f"CSP value: {csp_value[:100]}..." if len(csp_value) > 100 else f"CSP value: {csp_value}",
                owasp_refs=["A05:2021-Security Misconfiguration"]
            ))
            
        if "'unsafe-inline'" in csp_value:
            findings.append(Finding(
                title="CSP permissive (unsafe-inline)",
                severity=Severity.INFO,
                category=Category.HEADERS,
                description="The Content-Security-Policy allows 'unsafe-inline', which enables inline scripts and styles.",
                recommendation="Avoid using 'unsafe-inline' and use nonces or hashes instead.",
                evidence=f"CSP value: {csp_value[:100]}..." if len(csp_value) > 100 else f"CSP value: {csp_value}",
                owasp_refs=["A05:2021-Security Misconfiguration"]
            ))
        
    # X-Frame-Options
    if "x-frame-options" not in headers_lower:
        findings.append(Finding(
            title="Missing X-Frame-Options",
            severity=Severity.LOW,
            category=Category.HEADERS,
            description="The 'X-Frame-Options' header is missing. This header helps prevent Clickjacking attacks.",
            recommendation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
        
    # X-Content-Type-Options
    if "x-content-type-options" not in headers_lower:
        findings.append(Finding(
            title="Missing X-Content-Type-Options",
            severity=Severity.LOW,
            category=Category.HEADERS,
            description="The 'X-Content-Type-Options' header is missing. This prevents the browser from MIME-sniffing a response away from the declared content-type.",
            recommendation="Add 'X-Content-Type-Options: nosniff'.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
        
    # Referrer-Policy
    if "referrer-policy" not in headers_lower:
        findings.append(Finding(
            title="Missing Referrer-Policy",
            severity=Severity.INFO,
            category=Category.HEADERS,
            description="The 'Referrer-Policy' header is missing. This controls how much referrer information is sent with requests.",
            recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or similar.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))
        
    # Permissions-Policy
    if "permissions-policy" not in headers_lower:
        findings.append(Finding(
            title="Missing Permissions-Policy",
            severity=Severity.INFO,
            category=Category.HEADERS,
            description="The 'Permissions-Policy' header is missing. This allows you to enable or disable certain browser features.",
            recommendation="Add a Permissions-Policy header to restrict access to sensitive features like camera, microphone, etc.",
            owasp_refs=["A05:2021-Security Misconfiguration"]
        ))

    return findings

def check_cors(headers: Dict[str, str]) -> tuple[List[Finding], Dict[str, any]]:
    """
    Analyzes CORS headers for dangerous configurations.
    Returns a list of findings and a dictionary with raw CORS info.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    cors_info = {
        "allow_origin": headers_lower.get("access-control-allow-origin"),
        "allow_credentials": headers_lower.get("access-control-allow-credentials"),
        "vary": headers_lower.get("vary"),
        "notes": []
    }
    
    allow_origin = cors_info["allow_origin"]
    allow_credentials = cors_info["allow_credentials"]
    
    # Convert 'true' string to boolean for easier logic, or keep as string check
    credentials_true = allow_credentials and allow_credentials.lower() == "true"
    
    if allow_origin == "*" and credentials_true:
        note = "Potentially dangerous CORS: wildcard origin with credentials"
        cors_info["notes"].append(note)
        
        findings.append(Finding(
            title="Configuration CORS dangereuse",
            severity=Severity.HIGH,
            category=Category.HEADERS,
            description="The server allows access from any origin ('*') while also allowing credentials (cookies, auth headers). This is a critical security risk.",
            recommendation="Restrict 'Access-Control-Allow-Origin' to a whitelist of trusted domains and avoid using wildcard with credentials.",
            evidence=f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_credentials}",
            owasp_refs=["A05:2021-Security Misconfiguration", "A01:2021-Broken Access Control"]
        ))
        
    return findings, cors_info

