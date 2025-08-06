from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Union
from datetime import datetime

# Request models
class DirectoryScanRequest(BaseModel):
    path: str
    recursive: bool = True
    scan_id: Optional[str] = None

class ProcessScanRequest(BaseModel):
    scan_id: Optional[str] = None

class SystemScanRequest(BaseModel):
    include_processes: bool = True
    include_startup: bool = True
    include_common_dirs: bool = True
    scan_id: Optional[str] = None

# Response models
class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float = 0
    start_time: datetime
    end_time: Optional[datetime] = None
    target: Optional[str] = None
    message: Optional[str] = None

class ThreatInfo(BaseModel):
    name: str
    type: str
    risk_level: str
    description: str
    file_path: Optional[str] = None
    hash: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    status: str
    start_time: datetime
    end_time: Optional[datetime] = None
    scan_duration: Optional[float] = None
    threats_found: int = 0
    files_scanned: int = 0
    threats: List[ThreatInfo] = []
    summary: Dict[str, Any] = {}

class SystemInfo(BaseModel):
    cpu_usage: float
    memory_usage: float
    memory_total: int
    memory_available: int
    disk_usage: float
    disk_total: int
    disk_free: int
    active_processes: int
    timestamp: datetime
