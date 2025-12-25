from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Union

from ..constants import Severity, Category, LogLevel, ScanStatus, VisibilityLevel


@dataclass
class Finding:
    title: str
    severity: Union[Severity, str]  # Accept both for compatibility
    category: Union[Category, str]  # Accept both for compatibility
    description: str
    recommendation: str
    evidence: Optional[str] = None
    owasp_refs: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: "")
    
    def __post_init__(self):
        """Normalize severity and category to enum values."""
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)
        if isinstance(self.category, str):
            self.category = Category.from_string(self.category)


@dataclass
class ScanLogEntry:
    timestamp: datetime
    level: Union[LogLevel, str]  # Accept both for compatibility
    message: str
    
    def __post_init__(self):
        """Normalize level to enum."""
        if isinstance(self.level, str):
            self.level = LogLevel(self.level.upper())


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
    scan_status: Union[ScanStatus, str] = ScanStatus.OK
    blocking_mechanism: Optional[str] = None
    visibility_level: Union[VisibilityLevel, str] = VisibilityLevel.GOOD
    
    def __post_init__(self):
        """Normalize status and visibility to enums."""
        if isinstance(self.scan_status, str):
            try:
                self.scan_status = ScanStatus(self.scan_status)
            except ValueError:
                self.scan_status = ScanStatus.OK
        if isinstance(self.visibility_level, str):
            try:
                self.visibility_level = VisibilityLevel(self.visibility_level)
            except ValueError:
                self.visibility_level = VisibilityLevel.GOOD

