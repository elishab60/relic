from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, List, Optional

Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal["tls", "headers", "cookies", "exposure", "xss", "sqli", "availability", "error"]

@dataclass
class Finding:
    title: str
    severity: Severity
    category: Category
    description: str
    recommendation: str
    evidence: Optional[str] = None
    owasp_refs: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: "") # Can be generated if needed

@dataclass
class ScanLogEntry:
    timestamp: datetime
    level: Literal["INFO", "WARNING", "ERROR"]
    message: str

@dataclass
class ScanResult:
    target: str
    grade: str
    score: int
    findings: List[Finding]
    logs: List[ScanLogEntry]
    scanned_at: datetime
    response_time_ms: Optional[int] = None
    debug_info: Optional[dict] = None
    scan_status: str = "ok"
    blocking_mechanism: Optional[str] = None
    visibility_level: str = "good"
