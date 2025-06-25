from fastapi import FastAPI, File, UploadFile, BackgroundTasks, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import hashlib
import psutil
import asyncio
import uvicorn
import aiofiles
import shutil
import httpx
from datetime import datetime
import time
from typing import Optional, List, Dict, Any, Union
import threading
from pathlib import Path
import subprocess
import json

# Local imports
from scanner import MalwareScanner, FileScanner, DirectoryScanner, ProcessScanner, SystemScanner
import config
import models

# Create FastAPI app
app = FastAPI(
    title="ProtectIT Scanner Service",
    description="Advanced Malware Detection Engine with ML capabilities",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scanner
malware_scanner = MalwareScanner()

# Active scans dictionary to track ongoing scans
active_scans = {}

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    # Check if ML model exists, if not train or download it
    malware_scanner.initialize_ml_model()
    
    # Create required directories
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    print(f"Scanner service initialized. Upload directory: {config.UPLOAD_DIR}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/system-info")
async def get_system_info():
    """Get current system information"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        system_info = {
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "memory_total": memory.total,
            "memory_available": memory.available,
            "disk_usage": disk.percent,
            "disk_total": disk.total,
            "disk_free": disk.free,
            "active_processes": len(psutil.pids()),
            "timestamp": datetime.now().isoformat()
        }
        
        return system_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting system info: {str(e)}")

@app.post("/scan/file")
async def scan_file(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    scan_id: str = Form(None)
):
    """Scan a single file for malware"""
    if not scan_id:
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    try:
        # Save the uploaded file
        file_path = os.path.join(config.UPLOAD_DIR, file.filename)
        async with aiofiles.open(file_path, 'wb') as out_file:
            content = await file.read()  # async read
            await out_file.write(content)
        
        # Start a background scan task
        background_tasks.add_task(
            process_file_scan,
            file_path=file_path,
            scan_id=scan_id,
            original_filename=file.filename
        )
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": f"Scan initiated for file: {file.filename}",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.post("/scan/directory")
async def scan_directory(request: models.DirectoryScanRequest, background_tasks: BackgroundTasks):
    """Scan a directory for malware"""
    if not os.path.exists(request.path):
        raise HTTPException(status_code=404, detail="Directory not found")
    
    scan_id = request.scan_id or datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Start a background scan task
    background_tasks.add_task(
        process_directory_scan,
        directory_path=request.path,
        scan_id=scan_id,
        recursive=request.recursive
    )
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scan initiated for directory: {request.path}",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/scan/processes")
async def scan_processes(request: models.ProcessScanRequest, background_tasks: BackgroundTasks):
    """Scan running processes for suspicious activity"""
    scan_id = request.scan_id or datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Start a background scan task
    background_tasks.add_task(
        process_processes_scan,
        scan_id=scan_id
    )
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scanning system processes",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/scan/system")
async def scan_system(request: models.SystemScanRequest, background_tasks: BackgroundTasks):
    """Perform a full system scan"""
    scan_id = request.scan_id or datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Check if a system scan is already running
    if any(scan_info['type'] == 'system' for scan_info in active_scans.values()):
        raise HTTPException(status_code=400, detail="A system scan is already running")
    
    # Start a background scan task
    background_tasks.add_task(
        process_system_scan,
        scan_id=scan_id,
        include_processes=request.include_processes,
        include_startup=request.include_startup,
        include_common_dirs=request.include_common_dirs
    )
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Full system scan initiated",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    if scan_id in active_scans:
        return active_scans[scan_id]
    else:
        # Check if scan was completed and we have results
        # This would need to query the database or cache
        return {
            "scan_id": scan_id,
            "status": "unknown",
            "message": "Scan not found or completed",
            "timestamp": datetime.now().isoformat()
        }

@app.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel an ongoing scan"""
    if scan_id in active_scans:
        # TODO: Implement proper scan cancellation logic
        active_scans[scan_id]['status'] = 'cancelled'
        active_scans[scan_id]['message'] = 'Scan cancelled by user'
        return {"success": True, "message": "Scan cancelled"}
    else:
        raise HTTPException(status_code=404, detail="Scan not found or already completed")

# Background processing functions

async def process_file_scan(file_path: str, scan_id: str, original_filename: str):
    """Process file scan in the background"""
    try:
        # Register as active scan
        active_scans[scan_id] = {
            "scan_id": scan_id,
            "type": "file",
            "target": original_filename,
            "status": "in_progress",
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "message": f"Scanning file: {original_filename}"
        }
        
        # Update progress via webhook
        await send_progress_update(scan_id, 0, original_filename)
        
        # Create a scanner for this file
        file_scanner = FileScanner(file_path)
        
        # Scan the file
        results = await file_scanner.scan_file()
        
        # Send 100% progress update
        await send_progress_update(scan_id, 100, original_filename)
        
        # Send results via webhook
        await send_scan_results(scan_id, results)
        
        # Remove from active scans
        del active_scans[scan_id]
        
        print(f"Scan {scan_id} completed: {original_filename}")
        return results
    
    except Exception as e:
        # Send error via webhook
        error_result = {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        await send_scan_results(scan_id, error_result)
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        print(f"Error scanning {original_filename}: {str(e)}")
        return error_result

async def process_directory_scan(directory_path: str, scan_id: str, recursive: bool = True):
    """Process directory scan in the background"""
    try:
        # Register as active scan
        active_scans[scan_id] = {
            "scan_id": scan_id,
            "type": "directory",
            "target": directory_path,
            "status": "in_progress",
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "message": f"Scanning directory: {directory_path}"
        }
        
        # Create a scanner for this directory
        directory_scanner = DirectoryScanner(directory_path, recursive=recursive)
        
        # Count files to track progress
        total_files = directory_scanner.count_files()
        files_scanned = 0
        
        # Progress update function
        async def update_progress(file_path, is_threat=False):
            nonlocal files_scanned
            files_scanned += 1
            progress = min(int((files_scanned / max(total_files, 1)) * 100), 100)
            
            active_scans[scan_id]['progress'] = progress
            active_scans[scan_id]['current_file'] = file_path
            
            # Only send webhook updates periodically to avoid flooding
            if progress % 5 == 0 or is_threat:
                await send_progress_update(scan_id, progress, file_path)
        
        # Scan the directory
        results = await directory_scanner.scan_directory(progress_callback=update_progress)
        
        # Send 100% progress update
        await send_progress_update(scan_id, 100, directory_path)
        
        # Send results via webhook
        await send_scan_results(scan_id, results)
        
        # Remove from active scans
        del active_scans[scan_id]
        
        print(f"Directory scan {scan_id} completed: {directory_path}")
        return results
    
    except Exception as e:
        # Send error via webhook
        error_result = {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        await send_scan_results(scan_id, error_result)
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        print(f"Error scanning directory {directory_path}: {str(e)}")
        return error_result

async def process_processes_scan(scan_id: str):
    """Process running processes scan in the background"""
    try:
        # Register as active scan
        active_scans[scan_id] = {
            "scan_id": scan_id,
            "type": "processes",
            "status": "in_progress",
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "message": "Scanning system processes"
        }
        
        # Send initial progress update
        await send_progress_update(scan_id, 0, "System processes")
        
        # Create a scanner for processes
        process_scanner = ProcessScanner()
        
        # Scan the processes
        results = await process_scanner.scan_processes()
        
        # Send 100% progress update
        await send_progress_update(scan_id, 100, "System processes")
        
        # Send results via webhook
        await send_scan_results(scan_id, results)
        
        # Remove from active scans
        del active_scans[scan_id]
        
        print(f"Process scan {scan_id} completed")
        return results
    
    except Exception as e:
        # Send error via webhook
        error_result = {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        await send_scan_results(scan_id, error_result)
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        print(f"Error scanning processes: {str(e)}")
        return error_result

async def process_system_scan(
    scan_id: str, 
    include_processes: bool = True,
    include_startup: bool = True,
    include_common_dirs: bool = True
):
    """Process full system scan in the background"""
    try:
        # Register as active scan
        active_scans[scan_id] = {
            "scan_id": scan_id,
            "type": "system",
            "status": "in_progress",
            "progress": 0,
            "start_time": datetime.now().isoformat(),
            "message": "Starting full system scan"
        }
        
        # Send initial progress update
        await send_progress_update(scan_id, 0, "System scan")
        
        # Create a system scanner
        system_scanner = SystemScanner(
            include_processes=include_processes,
            include_startup=include_startup,
            include_common_dirs=include_common_dirs
        )
        
        # Progress update function
        async def update_progress(progress, current_item):
            active_scans[scan_id]['progress'] = progress
            active_scans[scan_id]['current_item'] = current_item
            await send_progress_update(scan_id, progress, current_item)
        
        # Scan the system
        results = await system_scanner.scan_system(progress_callback=update_progress)
        
        # Send 100% progress update
        await send_progress_update(scan_id, 100, "Full system scan")
        
        # Send results via webhook
        await send_scan_results(scan_id, results)
        
        # Remove from active scans
        del active_scans[scan_id]
        
        print(f"System scan {scan_id} completed")
        return results
    
    except Exception as e:
        # Send error via webhook
        error_result = {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        await send_scan_results(scan_id, error_result)
        
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        print(f"Error during system scan: {str(e)}")
        return error_result

# Webhook functions to send updates to Node.js backend

async def send_progress_update(scan_id: str, progress: float, current_item: str):
    """Send scan progress update via webhook"""
    webhook_data = {
        "scanId": scan_id,
        "progress": progress,
        "currentItem": current_item,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.WEBHOOK_SCAN_PROGRESS_URL,
                json=webhook_data,
                timeout=5.0
            )
            
            if response.status_code != 200:
                print(f"Error sending progress update: {response.text}")
                
    except Exception as e:
        print(f"Failed to send progress webhook: {str(e)}")

async def send_scan_results(scan_id: str, results: dict):
    """Send scan results via webhook"""
    webhook_data = {
        "scanId": scan_id,
        "result": results,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config.WEBHOOK_SCAN_RESULT_URL,
                json=webhook_data,
                timeout=10.0
            )
            
            if response.status_code != 200:
                print(f"Error sending scan results: {response.text}")
                
    except Exception as e:
        print(f"Failed to send results webhook: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=config.API_HOST,
        port=config.API_PORT,
        reload=config.DEBUG
    )
