from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class ScanRequest(BaseModel):
    target: str

class ScanLog(BaseModel):
    timestamp: datetime
    level: str
    message: str

class Finding(BaseModel):
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    evidence: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    target: str
    status: str
    score: int
    grade: str
    findings: List[Finding]
    logs: List[ScanLog]
    timestamp: datetime
    response_time_ms: Optional[int] = None
    debug_info: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    scan_id: str
