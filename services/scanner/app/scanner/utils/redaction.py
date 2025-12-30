"""
Redaction utilities for sanitizing sensitive data in evidence.
"""
import re
import hashlib
from typing import Optional

# Patterns to redact (compiled for performance)
REDACTION_PATTERNS = [
    # AWS Access Keys (AKIA...)
    (re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE), '***REDACTED_AWS_KEY***'),
    # Generic API keys (API_KEY, api-key, apikey patterns)
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{1,})["\']?'), r'\1=***REDACTED***'),
    # Bearer tokens
    (re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]+'), r'\1***REDACTED***'),
    # Authorization header values
    (re.compile(r'(?i)(authorization\s*[=:]\s*)[^\s\n]+'), r'\1***REDACTED***'),
    # Password patterns
    (re.compile(r'(?i)(password|passwd|pwd|secret|db_password|mysql_pwd|postgres_password)\s*[=:]\s*["\']?([^\s\n"\']{1,})["\']?'), r'\1=***REDACTED***'),
    # Secret key patterns
    (re.compile(r'(?i)(secret[_-]?key|private[_-]?key)\s*[=:]\s*["\']?([^\s\n"\']{1,})["\']?'), r'\1=***REDACTED***'),
    # RSA Private Keys
    (re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), '***REDACTED_PRIVATE_KEY***'),
    # Cookie values (be conservative - only redact obvious session tokens)
    (re.compile(r'(?i)(cookie\s*[=:]\s*)[^\n]+'), r'\1***REDACTED***'),
]

# Maximum length for evidence snippets
MAX_EVIDENCE_SNIPPET_LENGTH = 400


def redact_secrets(text: str) -> str:
    """
    Redacts sensitive information from text.
    
    Replaces patterns matching:
    - AWS keys (AKIA...)
    - API keys
    - Bearer tokens
    - Passwords/secrets
    - Private keys
    - Cookie values
    
    Args:
        text: The text to redact
        
    Returns:
        Redacted text with sensitive values replaced
    """
    if not text:
        return text
    
    result = text
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    
    return result


def compute_evidence_hash(content: str) -> str:
    """
    Computes a SHA-256 hash of the content.
    
    This is used to create a deterministic fingerprint of evidence
    before redaction, allowing verification without exposing secrets.
    
    Args:
        content: The original (unredacted) content
        
    Returns:
        Hex-encoded SHA-256 hash
    """
    if not content:
        return ""
    return hashlib.sha256(content.encode('utf-8', errors='replace')).hexdigest()


def truncate_evidence(text: str, max_length: int = MAX_EVIDENCE_SNIPPET_LENGTH) -> str:
    """
    Truncates evidence to a maximum length, adding ellipsis if truncated.
    
    Args:
        text: The text to truncate
        max_length: Maximum allowed length (default: 400)
        
    Returns:
        Truncated text with "..." suffix if it exceeded max_length
    """
    if not text:
        return text
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + "..."


def prepare_evidence_snippet(raw_content: str) -> tuple[str, str]:
    """
    Prepares an evidence snippet from raw content.
    
    Performs:
    1. Hash computation on original content
    2. Redaction of secrets
    3. Truncation to max length
    
    Args:
        raw_content: The original response body or content
        
    Returns:
        Tuple of (redacted_snippet, original_hash)
    """
    if not raw_content:
        return ("", "")
    
    # 1. Compute hash BEFORE any modification
    evidence_hash = compute_evidence_hash(raw_content)
    
    # 2. Redact secrets
    redacted = redact_secrets(raw_content)
    
    # 3. Truncate to max length
    snippet = truncate_evidence(redacted)
    
    return (snippet, evidence_hash)
