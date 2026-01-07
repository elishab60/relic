"""
Centralized Constants & Enums
=============================
This module defines canonical constants for the scanner service.
All severity levels, log levels, categories, and statuses are defined here.

IMPORTANT: Do NOT use string literals for these values elsewhere in the codebase.
Always import and use these enums to ensure consistency.

Version: 1.0.0
Last Updated: 2024-12-25
"""

from enum import Enum
from typing import Dict


class Severity(str, Enum):
    """
    Canonical severity levels for security findings.
    
    Ordered from least to most severe: INFO < LOW < MEDIUM < HIGH < CRITICAL
    
    Usage:
        from app.constants import Severity
        finding = Finding(severity=Severity.HIGH, ...)
    """
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """
        Convert a string to Severity enum, case-insensitive.
        
        Args:
            value: String like "high", "HIGH", "High", etc.
            
        Returns:
            Corresponding Severity enum value
            
        Raises:
            ValueError: If the string doesn't match any severity
        """
        normalized = value.lower().strip()
        try:
            return cls(normalized)
        except ValueError:
            raise ValueError(
                f"Invalid severity '{value}'. "
                f"Must be one of: {', '.join(s.value for s in cls)}"
            )
    
    @classmethod
    def values(cls) -> list:
        """Return all severity values as strings."""
        return [s.value for s in cls]
    
    def __str__(self) -> str:
        return self.value
    
    @property
    def level(self) -> int:
        """Return numeric level for comparison (INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4)."""
        _levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return _levels.get(self.value, 0)
    
    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level >= other.level
    
    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level > other.level
    
    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level <= other.level
    
    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level < other.level


class LogLevel(str, Enum):
    """Log levels for scan entries."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    
    def __str__(self) -> str:
        return self.value


class Category(str, Enum):
    """Categories for security findings."""
    TLS = "tls"
    HEADERS = "headers"
    COOKIES = "cookies"
    EXPOSURE = "exposure"
    XSS = "xss"
    SQLI = "sqli"
    CORS = "cors"
    AVAILABILITY = "availability"
    ERROR = "error"
    NETWORK = "network"
    
    @classmethod
    def from_string(cls, value: str) -> "Category":
        """Convert a string to Category enum, case-insensitive."""
        normalized = value.lower().strip()
        try:
            return cls(normalized)
        except ValueError:
            raise ValueError(
                f"Invalid category '{value}'. "
                f"Must be one of: {', '.join(c.value for c in cls)}"
            )
    
    def __str__(self) -> str:
        return self.value


class ScanStatus(str, Enum):
    """Status of a scan operation."""
    OK = "ok"
    FAILED = "failed"
    BLOCKED = "blocked"
    ERROR = "error"
    TIMEOUT = "timeout"
    
    def __str__(self) -> str:
        return self.value


class VisibilityLevel(str, Enum):
    """Visibility level for scan results."""
    GOOD = "good"
    LIMITED = "limited"
    BLOCKED = "blocked"
    
    def __str__(self) -> str:
        return self.value


class RiskLevel(str, Enum):
    """French risk levels for AI reports."""
    TRES_FAIBLE = "très faible"
    FAIBLE = "faible"
    MOYEN = "moyen"
    ELEVE = "élevé"
    CRITIQUE = "critique"
    
    @classmethod
    def from_string(cls, value: str) -> "RiskLevel":
        """Convert a string to RiskLevel enum, normalizing common variations."""
        normalized = value.lower().strip()
        # Handle common typos/variations
        mapping = {
            "tres faible": cls.TRES_FAIBLE,
            "très faible": cls.TRES_FAIBLE,
            "faible": cls.FAIBLE,
            "moyen": cls.MOYEN,
            "eleve": cls.ELEVE,
            "élevé": cls.ELEVE,
            "élevée": cls.ELEVE,
            "elevé": cls.ELEVE,
            "critique": cls.CRITIQUE,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"Invalid risk level '{value}'")
    
    def __str__(self) -> str:
        return self.value


# ============================================================================
# Severity Score Weights (for calculating overall score)
# ============================================================================

SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


# ============================================================================
# Frontend Mapping (for API serialization)
# ============================================================================

SEVERITY_TO_FRONTEND = {
    Severity.INFO: "info",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}

CATEGORY_TO_FRONTEND = {
    Category.TLS: "tls",
    Category.HEADERS: "headers",
    Category.COOKIES: "cookies",
    Category.EXPOSURE: "exposure",
    Category.XSS: "xss",
    Category.SQLI: "sqli",
    Category.CORS: "cors",
    Category.AVAILABILITY: "availability",
    Category.ERROR: "error",
    Category.NETWORK: "network",
}


# ============================================================================
# Color Mapping (for UI/PDF generation)
# ============================================================================

SEVERITY_COLORS = {
    Severity.CRITICAL: "#DC2626",  # Red 600
    Severity.HIGH: "#EA580C",      # Orange 600
    Severity.MEDIUM: "#CA8A04",    # Yellow 600
    Severity.LOW: "#2563EB",       # Blue 600
    Severity.INFO: "#6B7280",      # Gray 500
}


# ============================================================================
# OWASP References (common references)
# ============================================================================

OWASP_REFS = {
    "BROKEN_ACCESS_CONTROL": "A01:2021-Broken Access Control",
    "CRYPTO_FAILURES": "A02:2021-Cryptographic Failures",
    "INJECTION": "A03:2021-Injection",
    "INSECURE_DESIGN": "A04:2021-Insecure Design",
    "SECURITY_MISCONFIG": "A05:2021-Security Misconfiguration",
    "VULNERABLE_COMPONENTS": "A06:2021-Vulnerable and Outdated Components",
    "AUTH_FAILURES": "A07:2021-Identification and Authentication Failures",
    "DATA_INTEGRITY": "A08:2021-Software and Data Integrity Failures",
    "LOGGING_FAILURES": "A09:2021-Security Logging and Monitoring Failures",
    "SSRF": "A10:2021-Server-Side Request Forgery",
}
