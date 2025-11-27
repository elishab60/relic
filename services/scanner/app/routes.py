import asyncio
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, Response
from .models import ScanRequest, ScanResponse, ScanResult, ScanLog, Finding
from .store import scans
from .policy import is_authorized
from .sse import event_generator
from .pdf import generate_pdf

router = APIRouter()

from .scanner.engine import ScanEngine
from .scanner.models import ScanLogEntry

async def run_scan_task(scan_id: str, target: str):
    """Runs the real scan using ScanEngine."""
    engine = ScanEngine()
    
    # Initialize logs in store
    scans[scan_id]["logs"] = []
    
    async def log_callback(entry: ScanLogEntry):
        # Convert to dict for SSE/Store
        log_dict = {
            "timestamp": entry.timestamp.isoformat(),
            "level": entry.level,
            "message": entry.message
        }
        scans[scan_id]["logs"].append(log_dict)
        
    # Run the scan
    try:
        result = await engine.run_scan(target, log_callback)
        
        # Convert dataclass result to Pydantic model dict
        # We need to add scan_id and status which are not in the engine result
        
        findings_dicts = [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence": f.evidence
            } for f in result.findings
        ]
        
        logs_dicts = [
            {
                "timestamp": l.timestamp,
                "level": l.level,
                "message": l.message
            } for l in result.logs
        ]
        
        scan_result_dict = {
            "scan_id": scan_id,
            "target": result.target,
            "status": "done",
            "score": result.score,
            "grade": result.grade,
            "findings": findings_dicts,
            "logs": logs_dicts,
            "timestamp": result.scanned_at,
            "response_time_ms": result.response_time_ms,
            "debug_info": result.debug_info
        }
        
        scans[scan_id]["result"] = scan_result_dict
        scans[scan_id]["status"] = "done"
        
        # Generate PDF
        # We might need to update generate_pdf to handle new fields if it uses them
        # For now, let's assume it handles the dict or object. 
        # The generate_pdf function likely expects a Pydantic model or dict.
        # Let's instantiate the Pydantic model to be safe and pass it.
        
        pydantic_result = ScanResult(**scan_result_dict)
        pdf_bytes = generate_pdf(pydantic_result)
        scans[scan_id]["pdf"] = pdf_bytes
        
    except Exception as e:
        print(f"Scan failed: {e}")
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)

@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not is_authorized(request.target):
        raise HTTPException(status_code=403, detail="Target not authorized (Localhost/Private only)")
        
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"status": "running", "logs": [], "result": None, "pdf": None}
    
    background_tasks.add_task(run_scan_task, scan_id, request.target)
    
    return ScanResponse(scan_id=scan_id)

@router.get("/scan/{scan_id}/events")
async def scan_events(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return StreamingResponse(event_generator(scan_id, scans), media_type="text/event-stream")

@router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    data = scans[scan_id]
    if data["status"] != "done":
        return {"status": data["status"]}
        
    return data["result"]

@router.get("/scan/{scan_id}/report.pdf")
async def get_scan_pdf(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    data = scans[scan_id]
    if not data.get("pdf"):
        raise HTTPException(status_code=400, detail="PDF not ready")
        
    return Response(content=data["pdf"], media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"})
