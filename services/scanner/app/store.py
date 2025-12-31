from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlmodel import Session, select
from .database import engine
from .models import Scan, ScanResult, ScanLog, Finding

# Initialize DB
from .database import create_db_and_tables
create_db_and_tables()

# In-memory store for live logs of running scans
# scan_id -> list of log dicts
active_scans: Dict[str, List[Dict[str, Any]]] = {}

def create_scan(target: str, config_json: Dict[str, Any] = None) -> Scan:
    with Session(engine) as session:
        scan = Scan(target=target, status="queued", config_json=config_json)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        # Init active logs
        active_scans[scan.id] = []
        return scan

def get_scan(scan_id: str) -> Optional[Scan]:
    with Session(engine) as session:
        return session.get(Scan, scan_id)

def list_scans(limit: int = 100, offset: int = 0) -> List[Scan]:
    with Session(engine) as session:
        statement = select(Scan).order_by(Scan.started_at.desc()).offset(offset).limit(limit)
        return session.exec(statement).all()

def update_scan_status(scan_id: str, status: str):
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = status
            session.add(scan)
            session.commit()

def append_log(scan_id: str, log_entry: Dict[str, Any]):
    if scan_id in active_scans:
        active_scans[scan_id].append(log_entry)

def get_live_logs(scan_id: str) -> List[Dict[str, Any]]:
    return active_scans.get(scan_id, [])

def save_scan_result(scan_id: str, result: ScanResult):
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = "completed"
            scan.finished_at = datetime.utcnow()
            scan.score = result.score
            scan.grade = result.grade
            
            # Convert Pydantic models to dicts for JSON storage
            scan.result_json = result.model_dump(mode='json')
            scan.logs_json = [log.model_dump(mode='json') for log in result.logs]
            
            session.add(scan)
            session.commit()
            
            # Cleanup active logs
            if scan_id in active_scans:
                del active_scans[scan_id]

def fail_scan(scan_id: str, error_message: str):
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.finished_at = datetime.utcnow()
            session.add(scan)
            session.commit()
            
            # Cleanup active logs
            if scan_id in active_scans:
                del active_scans[scan_id]
