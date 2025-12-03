from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlmodel import Field, SQLModel, JSON
import uuid

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
    owasp_refs: List[str] = []

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
    scan_status: str = "ok"
    blocking_mechanism: Optional[str] = None
    visibility_level: str = "good"
    ai_analysis: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    scan_id: str

# DB Model
class Scan(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target: str
    status: str = Field(default="queued") # queued, running, completed, failed
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    
    # Storing complex objects as JSON
    result_json: Optional[Dict[str, Any]] = Field(default=None, sa_type=JSON)
    logs_json: List[Dict[str, Any]] = Field(default_factory=list, sa_type=JSON)
    
    # Summary fields for easy querying
    score: Optional[int] = None
    grade: Optional[str] = None

