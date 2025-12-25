"""
AI Report Schema Contract
=========================
This module defines the canonical schema for AI-generated security reports.
All AI outputs MUST be validated against these models before use.

Schema Version: 1.0.0
Last Updated: 2024-12-25

CRITICAL: Do not modify field names or types without updating:
- AI prompts in routes.py (AI_REPORT_SYSTEM_PROMPT)
- PDF generation in pdf.py
- Frontend consumers (if any)
"""

from typing import List, Optional, Literal
from pydantic import BaseModel, Field, field_validator, ConfigDict

from ..constants import Severity, RiskLevel


# For Pydantic validation, we still use Literal but reference the enum values
SeverityLevel = Literal["low", "medium", "high", "critical"]
RiskLevelLiteral = Literal["très faible", "faible", "moyen", "élevé", "critique"]



class AIGlobalScore(BaseModel):
    """Score representation for the security audit."""
    model_config = ConfigDict(extra="forbid")
    
    letter: str = Field(..., min_length=1, max_length=2)
    numeric: int = Field(..., ge=0, le=100)


class AIKeyVulnerability(BaseModel):
    """
    Individual vulnerability finding from AI analysis.
    
    Fields:
        title: Short, descriptive title of the vulnerability
        severity: Canonical severity level (low/medium/high/critical)
        area: Affected area (TLS, Headers, CORS, Network, etc.)
        explanation_simple: French explanation, 2-4 sentences
        fix_recommendation: Actionable fix recommendation in French
    """
    model_config = ConfigDict(extra="forbid")
    
    title: str = Field(..., min_length=1)
    severity: SeverityLevel
    area: str = Field(..., min_length=1)
    explanation_simple: str = Field(..., min_length=1)
    fix_recommendation: str = Field(..., min_length=1)
    
    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """Accept 'High', 'HIGH', etc. and normalize to lowercase."""
        if isinstance(v, str):
            return v.lower()
        return v


class AISiteMap(BaseModel):
    """Site map information from discovery phase."""
    model_config = ConfigDict(extra="forbid")
    
    total_pages: int = Field(default=0, ge=0)
    pages: List[str] = Field(default_factory=list)


class AIInfrastructure(BaseModel):
    """Infrastructure metadata extracted from scan."""
    model_config = ConfigDict(extra="forbid")
    
    hosting_provider: Optional[str] = None
    tls_issuer: Optional[str] = None
    server_header: Optional[str] = None
    ip: Optional[str] = None


class AIReport(BaseModel):
    """
    Main AI-generated security report schema.
    
    This is the CANONICAL structure that all AI outputs must conform to.
    Validation failure triggers fallback report generation.
    
    Fields:
        global_score: Letter grade (A-F) and numeric score (0-100)
        overall_risk_level: French risk level (très faible/faible/moyen/élevé/critique)
        executive_summary: French executive summary (5-8 sentences)
        key_vulnerabilities: List of top vulnerabilities (max 5)
        site_map: Discovered pages information
        infrastructure: Hosting/TLS/server metadata
        model_name: AI model used for analysis (injected post-validation)
    """
    model_config = ConfigDict(extra="forbid")
    
    global_score: AIGlobalScore
    overall_risk_level: RiskLevelLiteral
    executive_summary: str = Field(..., min_length=10)
    key_vulnerabilities: List[AIKeyVulnerability] = Field(default_factory=list)
    site_map: AISiteMap = Field(default_factory=AISiteMap)
    infrastructure: AIInfrastructure = Field(default_factory=AIInfrastructure)
    model_name: Optional[str] = None
    
    @field_validator("overall_risk_level", mode="before")
    @classmethod
    def normalize_risk_level(cls, v: str) -> str:
        """Normalize French risk levels to lowercase canonical form."""
        if isinstance(v, str):
            normalized = v.lower().strip()
            # Map common variations (missing accents, typos)
            mapping = {
                "tres faible": "très faible",
                "eleve": "élevé",
                "élevée": "élevé",
                "elevé": "élevé",
            }
            return mapping.get(normalized, normalized)
        return v
