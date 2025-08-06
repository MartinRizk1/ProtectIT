import os
import json
import time
import magic
import shutil
import logging
import hashlib
import threading
import subprocess
import platform
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import yara
from werkzeug.utils import secure_filename
import pefile
import psutil
from concurrent.futures import ThreadPoolExecutor
from ml_detector import MalwareDetector
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='scanner.log'
)
logger = logging.getLogger('scanner-service')

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
QUARANTINE_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'quarantine')
TEMP_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp')
YARA_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules')
MAX_THREADS = os.cpu_count() or 1  # Use all available CPU cores (fallback to 1)
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(TEMP_FOLDER, exist_ok=True)
os.makedirs(YARA_RULES_PATH, exist_ok=True)

# Global variables for scan status tracking
active_scans = {}
scan_results = {}

# Performance metrics
performance_metrics = {
    'total_scans': 0,
    'total_files_scanned': 0,
    'total_threats_found': 0,
    'avg_scan_time': 0,
    'total_scan_time': 0,
    'scans_per_minute': 0,
    'last_performance_update': time.time()
}

# Initialize ML detector
ml_detector = MalwareDetector()

# Create a basic YARA rule file if it doesn't exist
basic_yara_rule = """
rule suspicious_strings {
    strings:
        $cmd_exec = "WScript.Shell" nocase
        $registry = "RegWrite" nocase
        $download = "DownloadFile" nocase
        $create_object = "CreateObject" nocase
        $powershell = "powershell" nocase
        $exec = "cmd.exe" nocase
        $eval = "eval(" nocase
        $encoded_content = "base64" nocase
        
    condition:
        any of them
}

rule suspicious_executables {
    strings:
        $mz = "MZ"
        $pe = "PE\\x00\\x00"
        $suspicious_section = ".evil" nocase
        
    condition:
        ($mz at 0) and $pe and any of ($suspicious*)
}

rule potential_ransomware {
    strings:
        $encrypt_string1 = "encrypt" nocase
        $encrypt_string2 = "ransom" nocase
        $encrypt_string3 = "bitcoin" nocase
        $encrypt_string4 = "payment" nocase
        $encrypt_string5 = "decrypt" nocase
        
    condition:
        2 of ($encrypt_string*)
}

rule suspicious_scripts {
    strings:
        $obfuscation1 = "String.fromCharCode" nocase
        $obfuscation2 = "eval(atob" nocase
        $obfuscation3 = "document.write(unescape" nocase
        $obfuscation4 = "FromBase64String" nocase
        $obfuscation5 = "hidden iframe" nocase
        
    condition:
        any of them
}

rule suspicious_macro {
    strings:
        $auto_exec1 = "Auto_Open" nocase
        $auto_exec2 = "AutoOpen" nocase
        $auto_exec3 = "Document_Open" nocase
        $auto_exec4 = "AutoExec" nocase
        $auto_exec5 = "AutoClose" nocase
        $susp_function1 = "Shell" nocase
        $susp_function2 = "VBA.CreateObject" nocase
        $susp_function3 = "ActiveX" nocase
        
    condition:
        any of ($auto_exec*) and any of ($susp_function*)
}
"""

yara_rule_path = os.path.join(YARA_RULES_PATH, 'basic_rules.yar')
if not os.path.exists(yara_rule_path):
    with open(yara_rule_path, 'w') as f:
        f.write(basic_yara_rule)

# Load YARA rules
try:
    yara_rules = yara.compile(yara_rule_path)
except Exception as e:
    logger.error(f"Failed to compile YARA rules: {e}")
    yara_rules = None

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def get_file_metadata(file_path):
    """Get file metadata including type, size, and creation date."""
    file_stat = os.stat(file_path)
    file_type = magic.from_file(file_path)
    mime_type = magic.from_file(file_path, mime=True)
    
    return {
        'size': file_stat.st_size,
        'type': file_type,
        'mime_type': mime_type,
        'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
    }

def signature_detection(file_path):
    """Perform signature-based detection using YARA rules."""
    if not yara_rules:
        return {"detected": False, "signature": "YARA rules not loaded"}
    
    try:
        matches = yara_rules.match(file_path)
        if matches:
            return {
                "detected": True, 
                "signatures": [match.rule for match in matches],
                "details": str(matches)
            }
        return {"detected": False, "signature": None}
    except Exception as e:
        logger.error(f"Error in signature detection: {e}")
        return {"detected": False, "error": str(e)}

def heuristic_analysis(file_path):
    """Perform basic heuristic analysis."""
    suspicious_indicators = []
    risk_score = 0
    
    # Check file type vs extension
    file_name = os.path.basename(file_path)
    extension = os.path.splitext(file_name)[1].lower()
    mime_type = magic.from_file(file_path, mime=True)
    
    # Suspicious extension combinations
    suspicious_extensions = {
        '.exe': ['application/x-dosexec'],
        '.scr': ['application/x-dosexec'],
        '.dll': ['application/x-dosexec'],
        '.bat': ['text/plain'],
        '.vbs': ['text/plain'],
        '.ps1': ['text/plain'],
        '.js': ['text/plain', 'application/javascript'],
        '.doc': ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    }
    
    # Check if extension is in our suspicious list and verify the MIME type
    if extension in suspicious_extensions:
        if mime_type in suspicious_extensions[extension]:
            suspicious_indicators.append(f"Suspicious file: {extension} with {mime_type}")
            risk_score += 20
    
    # Check file content for specific patterns
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # Convert to string for text-based analysis, handle errors gracefully
        try:
            text_content = content.decode('utf-8', errors='ignore').lower()
            
            # Check for suspicious strings
            suspicious_strings = [
                "powershell -exec bypass", 
                "cmd.exe", 
                "wscript.shell",
                "eval(",
                "system(",
                "exec(",
                "document.write",
                "createobject",
                "shell.application",
                "regwrite",
                "downloadfile"
            ]
            
            for s in suspicious_strings:
                if s in text_content:
                    suspicious_indicators.append(f"Suspicious string: {s}")
                    risk_score += 15
                    
        except Exception as e:
            logger.warning(f"Error decoding file content: {e}")
        
        # Check for PE files (executables)
        if mime_type == 'application/x-dosexec':
            try:
                pe = pefile.PE(file_path)
                
                # Check for suspicious sections
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    if section_name in ['.evil', '.virus', '.malware', '.hack']:
                        suspicious_indicators.append(f"Suspicious PE section: {section_name}")
                        risk_score += 30
                
                # Check for suspicious imports
                suspicious_imports = ['wininet', 'urlmon', 'shell32', 'advapi32']
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    if any(imp in dll_name for imp in suspicious_imports):
                        suspicious_indicators.append(f"Suspicious import: {dll_name}")
                        risk_score += 10
                
                # Check for low entropy (may indicate packed or obfuscated code)
                if hasattr(pe, 'sections'):
                    for section in pe.sections:
                        entropy = section.get_entropy()
                        if entropy > 7.0:  # High entropy often indicates encryption/compression
                            suspicious_indicators.append(f"High entropy section: {entropy}")
                            risk_score += 25
                
            except Exception as e:
                logger.warning(f"Error analyzing PE file: {e}")
                
    except Exception as e:
        logger.error(f"Error in heuristic analysis: {e}")
    
    # Normalize risk score to a 0-100 scale
    risk_score = min(risk_score, 100)
    
    return {
        "risk_score": risk_score,
        "suspicious_indicators": suspicious_indicators,
        "risk_level": "High" if risk_score > 70 else "Medium" if risk_score > 40 else "Low"
    }

def quarantine_file(file_path):
    """Move file to quarantine and encrypt it with a secure key for isolation."""
    try:
        file_name = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_FOLDER, f"{file_name}.quarantine")
        
        # Generate a secure random key for each file
        import secrets
        xor_key = secrets.token_bytes(32)  # 256-bit key
        key_int = int.from_bytes(xor_key, byteorder='big')
        
        # More secure "encryption" with XOR using a unique key
        with open(file_path, 'rb') as f_in, open(quarantine_path, 'wb') as f_out:
            # XOR each byte with a rotating byte from the key
            data = f_in.read()
            key_bytes = xor_key * (len(data) // len(xor_key) + 1)
            encrypted = bytes(d ^ k for d, k in zip(data, key_bytes[:len(data)]))
            f_out.write(encrypted)
        
        # Create metadata file
        metadata = {
            'original_path': file_path,
            'quarantine_date': datetime.now().isoformat(),
            'file_hash': calculate_file_hash(file_path),
            'key_hash': hashlib.sha256(xor_key).hexdigest()  # Store hash of key for verification
        }
        
        # Store the actual key in a separate secure location
        key_path = f"{quarantine_path}.key"
        with open(key_path, 'wb') as f:
            f.write(xor_key)
        
        with open(f"{quarantine_path}.meta", 'w') as f:
            json.dump(metadata, f)
            
        logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to quarantine file {file_path}: {e}")
        return False

def scan_file(file_path, scan_id, detection_methods=None):
    """Scan a single file for threats."""
    try:
        start_time = time.time()
        
        # Default detection methods if not specified
        if detection_methods is None:
            detection_methods = {
                'signature': True,
                'heuristic': True,
                'ml': True
            }
        
        # Update scan status
        active_scans[scan_id]["status"] = "scanning"
        active_scans[scan_id]["files_processed"] += 1
        active_scans[scan_id]["current_file"] = os.path.basename(file_path)
        
        # Emit real-time update via WebSocket
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'file': os.path.basename(file_path),
            'processed': active_scans[scan_id]["files_processed"],
            'total': active_scans[scan_id]["files_total"]
        })
        
        file_hash = calculate_file_hash(file_path)
        metadata = get_file_metadata(file_path)
        
        # Perform detections based on selected methods
        signature_results = {"detected": False, "signature": None}
        heuristic_results = {"risk_score": 0, "suspicious_indicators": [], "risk_level": "Low"}
        ml_results = {"is_analyzed": False}
        
        if detection_methods.get('signature', True):
            signature_results = signature_detection(file_path)
        
        if detection_methods.get('heuristic', True):
            heuristic_results = heuristic_analysis(file_path)
        
        if detection_methods.get('ml', True):
            ml_results = ml_detector.predict(file_path, metadata['mime_type'])
        
        # Determine if file is malicious based on enabled detection methods
        is_malicious = False
        if detection_methods.get('signature', True) and signature_results["detected"]:
            is_malicious = True
        if detection_methods.get('heuristic', True) and heuristic_results["risk_level"] == "High":
            is_malicious = True
        if detection_methods.get('ml', True) and ml_results.get('is_analyzed', False) and ml_results.get('prediction', 0) == 1 and ml_results.get('confidence_pct', 0) > 70:
            is_malicious = True
        
        # Quarantine if malicious
        quarantine_info = None
        if is_malicious:
            quarantine_info = quarantine_file(file_path)
            active_scans[scan_id]["threats_found"] += 1
        
        # Calculate scan time
        scan_time = time.time() - start_time
        
        # Update performance metrics
        performance_metrics['total_files_scanned'] += 1
        performance_metrics['total_scan_time'] += scan_time
        if is_malicious:
            performance_metrics['total_threats_found'] += 1
        
        result = {
            "filename": os.path.basename(file_path),
            "filepath": file_path,
            "filesize": metadata["size"],
            "filetype": metadata["type"],
            "hash": file_hash,
            "scan_time": datetime.now().isoformat(),
            "scan_duration": scan_time,
            "signature_detection": signature_results if detection_methods.get('signature', True) else None,
            "heuristic_analysis": heuristic_results if detection_methods.get('heuristic', True) else None,
            "ml_analysis": ml_results if detection_methods.get('ml', True) and ml_results.get('is_analyzed', False) else None,
            "is_malicious": is_malicious,
            "quarantined": quarantine_info is not None and quarantine_info["success"] if quarantine_info else False,
            "quarantine_info": quarantine_info
        }
        
        # Add to scan results
        scan_results[scan_id]["files"].append(result)
        
        return result
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {e}")
        return {
            "filename": os.path.basename(file_path),
            "error": str(e),
            "is_malicious": False
        }

def scan_directory(directory_path, scan_id, max_depth=5):
    """Recursively scan a directory for threats."""
    if max_depth <= 0:
        logger.warning(f"Maximum recursion depth reached for {directory_path}")
        return
    
    try:
        files_to_scan = []
        for entry in os.scandir(directory_path):
            if active_scans[scan_id]["status"] == "cancelled":
                logger.info(f"Scan {scan_id} was cancelled")
                break
                
            if entry.is_file():
                files_to_scan.append(entry.path)
            elif entry.is_dir():
                scan_directory(entry.path, scan_id, max_depth - 1)
        
        # Use ThreadPoolExecutor to scan files in parallel
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            executor.map(lambda file_path: scan_file(file_path, scan_id), files_to_scan)
            
    except Exception as e:
        logger.error(f"Error scanning directory {directory_path}: {e}")

def scan_thread_function(file_paths, scan_id):
    """Thread function to scan multiple files in parallel."""
    try:
        files_to_scan = []
        dirs_to_scan = []
        
        # Separate files and directories
        for file_path in file_paths:
            if active_scans[scan_id]["status"] == "cancelled":
                break
                
            if os.path.isfile(file_path):
                files_to_scan.append(file_path)
            elif os.path.isdir(file_path):
                dirs_to_scan.append(file_path)
        
        # Scan files in parallel
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            executor.map(lambda file_path: scan_file(file_path, scan_id), files_to_scan)
        
        # Scan directories
        for dir_path in dirs_to_scan:
            if active_scans[scan_id]["status"] == "cancelled":
                break
            scan_directory(dir_path, scan_id)
        
        # Check if this is the last thread to complete
        active_scans[scan_id]["completed_threads"] += 1
        if active_scans[scan_id]["completed_threads"] >= active_scans[scan_id]["total_threads"]:
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["end_time"] = datetime.now().isoformat()
            active_scans[scan_id]["scan_duration"] = (
                datetime.fromisoformat(active_scans[scan_id]["end_time"]) - 
                datetime.fromisoformat(active_scans[scan_id]["start_time"])
            ).total_seconds()
            
            # Update performance metrics
            performance_metrics['total_scans'] += 1
            current_time = time.time()
            time_diff = current_time - performance_metrics['last_performance_update']
            
            if time_diff >= 60:  # Update scans per minute every minute
                performance_metrics['scans_per_minute'] = (
                    performance_metrics['total_scans'] / time_diff * 60
                )
                performance_metrics['last_performance_update'] = current_time
            
            performance_metrics['avg_scan_time'] = (
                performance_metrics['total_scan_time'] / 
                performance_metrics['total_files_scanned']
                if performance_metrics['total_files_scanned'] > 0 else 0
            )
            
            # Emit scan completion via WebSocket
            socketio.emit('scan_complete', {
                'scan_id': scan_id,
                'threats_found': active_scans[scan_id]["threats_found"],
                'total_files': active_scans[scan_id]["files_processed"],
                'scan_duration': active_scans[scan_id]["scan_duration"]
            })
            
            logger.info(f"Scan {scan_id} completed")
            
    except Exception as e:
        logger.error(f"Error in scan thread for scan {scan_id}: {e}")
        active_scans[scan_id]["status"] = "error"
        active_scans[scan_id]["error"] = str(e)

@app.route('/scan', methods=['POST'])
def scan_files():
    """API endpoint to scan files."""
    try:
        # Handle file upload
        if 'files[]' not in request.files:
            return jsonify({"error": "No files provided"}), 400
            
        files = request.files.getlist('files[]')
        
        # Generate scan ID
        scan_id = f"scan_{int(time.time())}_{os.urandom(4).hex()}"
        
        # Initialize scan status
        active_scans[scan_id] = {
            "id": scan_id,
            "status": "starting",
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "files_total": len(files),
            "files_processed": 0,
            "threats_found": 0,
            "current_file": None,
            "total_threads": min(MAX_THREADS, len(files)),
            "completed_threads": 0,
            "error": None,
            "scan_duration": 0
        }
        
        scan_results[scan_id] = {
            "id": scan_id,
            "files": []
        }
        
        # Save files and prepare paths for scanning
        file_paths = []
        for file in files:
            if file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(file_path)
                file_paths.append(file_path)
        
        # Divide files among threads for optimal parallel processing
        chunk_size = max(1, len(file_paths) // MAX_THREADS)
        file_chunks = [file_paths[i:i + chunk_size] for i in range(0, len(file_paths), chunk_size)]
        
        # Start scanning threads
        active_scans[scan_id]["total_threads"] = len(file_chunks)
        for chunk in file_chunks:
            thread = threading.Thread(target=scan_thread_function, args=(chunk, scan_id))
            thread.daemon = True
            thread.start()
        
        # Return scan ID for status checking
        return jsonify({
            "scan_id": scan_id,
            "status": "started",
            "message": f"Scan started with ID: {scan_id}"
        })
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of an ongoing scan."""
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    else:
        return jsonify({"error": "Scan ID not found"}), 404

@app.route('/scan/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """Get the results of a completed scan."""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    else:
        return jsonify({"error": "Scan results not found"}), 404

@app.route('/scan/cancel/<scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    """Cancel an ongoing scan."""
    if scan_id in active_scans:
        active_scans[scan_id]["status"] = "cancelled"
        return jsonify({"message": f"Scan {scan_id} cancelled"})
    else:
        return jsonify({"error": "Scan ID not found"}), 404

@app.route('/scan/history', methods=['GET'])
def get_scan_history():
    """Get summary of all scans (history)"""
    try:
        history = []
        for scan_id, info in active_scans.items():
            history.append({
                'scan_id': scan_id,
                'status': info.get('status'),
                'start_time': info.get('start_time'),
                'end_time': info.get('end_time'),
                'files_total': info.get('files_total'),
                'files_processed': info.get('files_processed'),
                'threats_found': info.get('threats_found'),
                'scan_duration': info.get('scan_duration')
            })
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/quarantine/list', methods=['GET'])
def list_quarantined():
    """List all quarantined files."""
    try:
        quarantined_files = []
        
        for entry in os.scandir(QUARANTINE_FOLDER):
            if entry.is_file() and entry.name.endswith('.quarantine'):
                meta_path = f"{entry.path}.meta"
                
                if os.path.exists(meta_path):
                    with open(meta_path, 'r') as f:
                        metadata = json.load(f)
                else:
                    metadata = {"error": "Metadata not found"}
                
                quarantined_files.append({
                    "filename": entry.name,
                    "quarantine_path": entry.path,
                    "metadata": metadata
                })
        
        return jsonify(quarantined_files)
    except Exception as e:
        logger.error(f"Error listing quarantined files: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/quarantine/restore/<filename>', methods=['POST'])
def restore_quarantine_file(filename):
    """Restore a file from quarantine."""
    try:
        quarantine_path = os.path.join(QUARANTINE_FOLDER, filename)
        if not os.path.exists(quarantine_path):
            return jsonify({"success": False, "message": "Quarantined file not found"}), 404
            
        # Load metadata
        metadata_path = f"{quarantine_path}.meta"
        if not os.path.exists(metadata_path):
            return jsonify({"success": False, "message": "Metadata file not found"}), 404
            
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            
        # Load the key
        key_path = f"{quarantine_path}.key"
        if not os.path.exists(key_path):
            return jsonify({"success": False, "message": "Key file not found"}), 404
            
        with open(key_path, 'rb') as f:
            xor_key = f.read()
            
        # Verify key integrity
        import hashlib
        key_hash = hashlib.sha256(xor_key).hexdigest()
        if key_hash != metadata.get('key_hash'):
            return jsonify({"success": False, "message": "Key integrity check failed"}), 400
            
        # Determine restoration path
        restore_path = metadata.get('original_path')
        if not restore_path or not os.path.exists(os.path.dirname(restore_path)):
            restore_path = os.path.join(TEMP_FOLDER, filename.replace('.quarantine', ''))
            
        # Restore file by reversing the XOR encryption
        with open(quarantine_path, 'rb') as f_in, open(restore_path, 'wb') as f_out:
            data = f_in.read()
            key_bytes = xor_key * (len(data) // len(xor_key) + 1)
            decrypted = bytes(d ^ k for d, k in zip(data, key_bytes[:len(data)]))
            f_out.write(decrypted)
                
        # Log the restoration
        logger.info(f"File restored from quarantine: {quarantine_path} -> {restore_path}")
        
        return jsonify({
            "success": True,
            "message": "File restored successfully",
            "restore_path": restore_path
        })
    except Exception as e:
        logger.error(f"Failed to restore file from quarantine: {e}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route('/quarantine/delete/<filename>', methods=['DELETE'])
def delete_quarantined(filename):
    """Permanently delete a quarantined file."""
    try:
        quarantine_path = os.path.join(QUARANTINE_FOLDER, filename)
        meta_path = f"{quarantine_path}.meta"
        
        if not os.path.exists(quarantine_path):
            return jsonify({"error": "Quarantined file not found"}), 404
            
        # Delete the quarantined file and its metadata
        os.remove(quarantine_path)
        if os.path.exists(meta_path):
            os.remove(meta_path)
            
        # Log the deletion
        logger.info(f"Quarantined file deleted: {quarantine_path}")
        
        return jsonify({
            "success": True,
            "message": f"File {filename} permanently deleted"
        })
    except Exception as e:
        logger.error(f"Error deleting quarantined file {filename}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/system/stats', methods=['GET'])
def get_system_stats():
    """Get system stats (CPU, memory, disk usage)."""
    try:
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.5)
        
        # Get memory usage
        memory = psutil.virtual_memory()
        mem_total = memory.total / (1024 * 1024)  # MB
        mem_used = memory.used / (1024 * 1024)    # MB
        mem_percent = memory.percent

        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_total = disk.total
        disk_used = disk.used
        disk_percent = disk.percent

        # Get active processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                pinfo = proc.info
                processes.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "user": pinfo['username'],
                    "cpu": pinfo['cpu_percent'],
                    "mem": pinfo['memory_percent'],
                    "command": ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Sort by CPU usage and get top 25
        processes = sorted(processes, key=lambda x: x["cpu"], reverse=True)[:25]

        # Get scanner performance metrics
        scanner_metrics = {
            "total_scans": performance_metrics["total_scans"],
            "total_files_scanned": performance_metrics["total_files_scanned"],
            "total_threats_found": performance_metrics["total_threats_found"],
            "avg_scan_time": performance_metrics["avg_scan_time"],
            "scans_per_minute": performance_metrics["scans_per_minute"],
            "detection_rate": (
                performance_metrics["total_threats_found"] / performance_metrics["total_files_scanned"]
                if performance_metrics["total_files_scanned"] > 0 else 0
            ) * 100
        }
        
        # Get ML detector metrics
        ml_metrics = ml_detector.get_benchmark_stats() if hasattr(ml_detector, 'get_benchmark_stats') else {}

        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "cpu": {
                "usage_percent": cpu_percent
            },
            "memory": {
                "total_mb": round(mem_total, 2),
                "used_mb": round(mem_used, 2),
                "usage_percent": round(mem_percent, 2)
            },
            "disk": {
                "total": disk_total,
                "used": disk_used,
                "usage_percent": disk_percent
            },
            "processes": processes,
            "scanner_performance": scanner_metrics,
            "ml_performance": ml_metrics
        })
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/network/connections', methods=['GET'])
def get_network_connections():
    """Get active network connections."""
    try:
        connections = []
        
        # Get network connections using psutil
        for conn in psutil.net_connections(kind='inet'):
            try:
                # Get process information if pid exists
                process_name = ""
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                    except:
                        pass
                        
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                connections.append({
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_address": local_address,
                    "foreign_address": remote_address,
                    "state": conn.status,
                    "pid": conn.pid,
                    "process": process_name
                })
            except:
                pass
        
        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "connections": connections
        })
    except Exception as e:
        logger.error(f"Error in network connections endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/ml/train', methods=['POST'])
def train_ml_model():
    """Train the ML model with benign and malicious samples."""
    try:
        data = request.get_json()
        benign_dir = data.get('benign_dir')
        malicious_dir = data.get('malicious_dir')
        framework = data.get('framework', 'all')  # Default to all frameworks
        
        if not benign_dir or not malicious_dir:
            return jsonify({"error": "Both benign_dir and malicious_dir must be provided"}), 400
            
        if not os.path.isdir(benign_dir) or not os.path.isdir(malicious_dir):
            return jsonify({"error": "Invalid directory paths provided"}), 400
            
        # Validate framework parameter
        valid_frameworks = ['all', 'scikit-learn', 'tensorflow', 'pytorch']
        if framework not in valid_frameworks:
            return jsonify({"error": f"Invalid framework. Must be one of: {', '.join(valid_frameworks)}"}), 400
        
        # Start training in a separate thread to avoid blocking the API
        def train_thread():
            # Train with the selected framework(s)
            training_options = {
                'train_sklearn': framework in ['all', 'scikit-learn'],
                'train_pytorch': framework in ['all', 'pytorch'],
                'train_tensorflow': framework in ['all', 'tensorflow']
            }
            
            result = ml_detector.train_model(benign_dir, malicious_dir, **training_options)
            socketio.emit('ml_training_complete', result)
            
        training_thread = threading.Thread(target=train_thread)
        training_thread.daemon = True
        training_thread.start()
        
        return jsonify({
            "success": True,
            "message": "ML training started",
            "status": "Training started in background, you will be notified when complete"
        })
        
    except Exception as e:
        logger.error(f"Error training ML model: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/ml/stats', methods=['GET'])
def get_ml_stats():
    """Get ML model statistics."""
    try:
        import sys
        
        # Check for different model types
        sklearn_model_path = os.path.join(ml_detector.model_dir, 'malware_model.pkl')
        pytorch_model_path = os.path.join(ml_detector.model_dir, 'malware_nn_model.pth')
        
        sklearn_model_exists = os.path.exists(sklearn_model_path)
        pytorch_model_exists = os.path.exists(pytorch_model_path)
        
        # Get active frameworks
        active_frameworks = []
        if sklearn_model_exists:
            active_frameworks.append("scikit-learn")
        if pytorch_model_exists:
            active_frameworks.append("pytorch")
        try:
            import tensorflow
            active_frameworks.append("tensorflow")
        except ImportError:
            pass
        
        # Get last trained date (most recent of any model)
        last_trained = None
        if sklearn_model_exists:
            sklearn_model_stat = os.stat(sklearn_model_path)
            sklearn_model_date = datetime.fromtimestamp(sklearn_model_stat.st_mtime).isoformat()
            last_trained = sklearn_model_date
        
        if pytorch_model_exists:
            pytorch_model_stat = os.stat(pytorch_model_path)
            pytorch_model_date = datetime.fromtimestamp(pytorch_model_stat.st_mtime).isoformat()
            if not last_trained or pytorch_model_date > last_trained:
                last_trained = pytorch_model_date
        
        # Try to load feature importances if available
        feature_importances = []
        fi_path = os.path.join(ml_detector.model_dir, 'feature_importances.csv')
        if os.path.exists(fi_path):
            try:
                import pandas as pd
                fi_df = pd.read_csv(fi_path)
                feature_importances = fi_df.head(10).to_dict('records')
            except Exception as e:
                logger.error(f"Error loading feature importances: {e}")
        
        # Get benchmark stats
        bench_stats = {}
        if hasattr(ml_detector, 'get_benchmark_stats'):
            try:
                bench_stats = ml_detector.get_benchmark_stats()
            except Exception as e:
                logger.error(f"Error getting benchmark stats: {e}")
        
        # Calculate basic metrics even if no benchmark stats method
        total_predictions = ml_detector.scan_count
        malware_detected = ml_detector.detection_count
        avg_detection_time = ml_detector.total_scan_time / total_predictions if total_predictions > 0 else 0
        
        if sklearn_model_exists or pytorch_model_exists:
            return jsonify({
                "sklearn_model_loaded": ml_detector.model is not None,
                "pytorch_model_loaded": ml_detector.nn_model is not None,
                "sklearn_model_exists": sklearn_model_exists,
                "pytorch_model_exists": pytorch_model_exists,
                "frameworks": active_frameworks,
                "last_trained": last_trained,
                "feature_importances": feature_importances,
                "metrics": bench_stats,
                "total_predictions": total_predictions,
                "malware_detected": malware_detected,
                "avg_detection_time": avg_detection_time * 1000,  # Convert to milliseconds
                "avg_confidence": bench_stats.get("avg_confidence", 0) * 100 if bench_stats else 0,
                "accuracy": bench_stats.get("accuracy", 0) if bench_stats else 0,
                "training_dataset_size": bench_stats.get("training_dataset_size", 0) if bench_stats else 0
            })
        else:
            return jsonify({
                "model_loaded": False,
                "model_exists": False,
                "message": "ML model not found. Please train the model first.",
                "frameworks": active_frameworks,
                "total_predictions": 0,
                "malware_detected": 0,
                "avg_detection_time": 0,
                "avg_confidence": 0
            })
    except Exception as e:
        logger.error(f"Error getting ML stats: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def home():
    """Home endpoint to check if the service is running."""
    return jsonify({
        "status": "running",
        "message": "ProtectIT Scanner Service is running",
        "version": "1.0.0",
        "threads_available": MAX_THREADS
    })

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    logger.info(f"Client disconnected: {request.sid}")

# Add system-wide scanning functions
def get_system_scan_paths():
    """Get common system paths to scan for malware"""
    import platform
    system = platform.system().lower()
    
    if system == "windows":
        return [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64", 
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Users",
            "C:\\ProgramData",
            "C:\\Temp",
            "C:\\Windows\\Temp"
        ]
    elif system == "darwin":  # macOS
        return [
            "/Applications",
            "/System/Library",
            "/Library",
            "/usr/bin",
            "/usr/local/bin",
            "/tmp",
            "/var/tmp",
            "/Users"
        ]
    else:  # Linux and other Unix-like systems
        return [
            "/usr/bin",
            "/usr/local/bin", 
            "/bin",
            "/sbin",
            "/opt",
            "/tmp",
            "/var/tmp",
            "/home"
        ]

def scan_system_paths(scan_id, paths=None, max_files=10000):
    """Scan system paths for malware with file limit to prevent overwhelming"""
    if paths is None:
        paths = get_system_scan_paths()
    
    files_scanned = 0
    total_files_found = 0
    
    # First pass: count total files to scan
    for path in paths:
        if active_scans[scan_id]["status"] == "cancelled":
            break
        if os.path.exists(path):
            try:
                for root, dirs, files in os.walk(path):
                    # Skip system-protected directories that might cause permission errors
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'System Volume Information']
                    total_files_found += len(files)
                    if total_files_found > max_files:
                        break
                if total_files_found > max_files:
                    break
            except (PermissionError, OSError):
                continue
    
    # Update scan info with actual file count
    active_scans[scan_id]["files_total"] = min(total_files_found, max_files)
    
    # Second pass: actually scan the files
    for path in paths:
        if active_scans[scan_id]["status"] == "cancelled":
            break
        if os.path.exists(path):
            try:
                for root, dirs, files in os.walk(path):
                    # Skip system-protected directories
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'System Volume Information']
                    
                    for file in files:
                        if files_scanned >= max_files or active_scans[scan_id]["status"] == "cancelled":
                            break
                        
                        file_path = os.path.join(root, file)
                        try:
                            # Skip very large files to avoid performance issues
                            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                                continue
                            
                            # Scan the file
                            scan_file(file_path, scan_id)
                            files_scanned += 1
                            
                        except (PermissionError, OSError, FileNotFoundError):
                            # Skip files we can't access
                            continue
                    
                    if files_scanned >= max_files:
                        break
                        
            except (PermissionError, OSError):
                logger.warning(f"Permission denied or error accessing: {path}")
                continue
    
    return files_scanned

@app.route('/scan/system', methods=['POST'])
def scan_system():
    """API endpoint to scan the entire system for malware."""
    try:
        data = request.get_json() or {}
        scan_type = data.get('scan_type', 'quick')  # quick, full, custom
        max_files = data.get('max_files', 10000)  # Limit files to scan
        custom_paths = data.get('custom_paths', [])  # Custom paths for scanning
        
        # Generate scan ID
        scan_id = f"system_scan_{int(time.time())}_{os.urandom(4).hex()}"
        
        # Determine paths to scan
        if scan_type == 'custom' and custom_paths:
            scan_paths = custom_paths
        elif scan_type == 'full':
            scan_paths = get_system_scan_paths()
            max_files = 50000  # Allow more files for full scan
        else:  # quick scan
            scan_paths = get_system_scan_paths()[:3]  # Scan only first 3 critical paths
            max_files = 5000
        
        # Initialize scan status
        active_scans[scan_id] = {
            "id": scan_id,
            "status": "starting",
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "scan_type": "system",
            "files_total": 0,  # Will be updated by scan_system_paths
            "files_processed": 0,
            "threats_found": 0,
            "current_file": None,
            "total_threads": 1,
            "completed_threads": 0,
            "error": None,
            "scan_duration": 0,
            "scan_paths": scan_paths,
            "max_files": max_files
        }
        
        scan_results[scan_id] = {
            "id": scan_id,
            "files": []
        }
        
        # Start system scan in a separate thread
        def system_scan_thread():
            try:
                active_scans[scan_id]["status"] = "scanning"
                files_scanned = scan_system_paths(scan_id, scan_paths, max_files)
                
                # Mark scan as completed
                active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["end_time"] = datetime.now().isoformat()
                active_scans[scan_id]["scan_duration"] = (
                    datetime.fromisoformat(active_scans[scan_id]["end_time"]) - 
                    datetime.fromisoformat(active_scans[scan_id]["start_time"])
                ).total_seconds()
                
                # Emit completion via WebSocket
                socketio.emit('scan_complete', {
                    'scan_id': scan_id,
                    'status': 'completed',
                    'files_scanned': files_scanned,
                    'threats_found': active_scans[scan_id]["threats_found"]
                })
                
            except Exception as e:
                logger.error(f"System scan error: {e}")
                active_scans[scan_id]["status"] = "error"
                active_scans[scan_id]["error"] = str(e)
                socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)})
        
        thread = threading.Thread(target=system_scan_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "scan_id": scan_id,
            "status": "started",
            "message": f"System scan started with ID: {scan_id}",
            "scan_type": scan_type,
            "max_files": max_files,
            "scan_paths": scan_paths
        })
        
    except Exception as e:
        logger.error(f"Error in system scan endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/scan/quick-system', methods=['POST'])
def quick_system_scan():
    """Quick system scan of critical directories only."""
    try:
        # Generate scan ID
        scan_id = f"quick_scan_{int(time.time())}_{os.urandom(4).hex()}"
        
        # Critical paths for quick scan
        import platform
        system = platform.system().lower()
        
        if system == "windows":
            critical_paths = ["C:\\Windows\\System32", "C:\\Program Files", "C:\\Users\\Public"]
        elif system == "darwin":
            critical_paths = ["/Applications", "/tmp", "/Library"]
        else:
            critical_paths = ["/usr/bin", "/tmp", "/opt"]
        
        # Initialize scan
        active_scans[scan_id] = {
            "id": scan_id,
            "status": "starting",
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "scan_type": "quick_system",
            "files_total": 1000,  # Estimated for quick scan
            "files_processed": 0,
            "threats_found": 0,
            "current_file": None,
            "total_threads": 1,
            "completed_threads": 0,
            "error": None,
            "scan_duration": 0
        }
        
        scan_results[scan_id] = {"id": scan_id, "files": []}
        
        # Start quick scan thread
        def quick_scan_thread():
            try:
                active_scans[scan_id]["status"] = "scanning"
                files_scanned = scan_system_paths(scan_id, critical_paths, 1000)
                
                active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["end_time"] = datetime.now().isoformat()
                active_scans[scan_id]["scan_duration"] = (
                    datetime.fromisoformat(active_scans[scan_id]["end_time"]) - 
                    datetime.fromisoformat(active_scans[scan_id]["start_time"])
                ).total_seconds()
                
                socketio.emit('scan_complete', {
                    'scan_id': scan_id,
                    'status': 'completed',
                    'files_scanned': files_scanned,
                    'threats_found': active_scans[scan_id]["threats_found"]
                })
                
            except Exception as e:
                logger.error(f"Quick scan error: {e}")
                active_scans[scan_id]["status"] = "error"
                active_scans[scan_id]["error"] = str(e)
        
        thread = threading.Thread(target=quick_scan_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "scan_id": scan_id,
            "status": "started",
            "message": f"Quick system scan started with ID: {scan_id}"
        })
        
    except Exception as e:
        logger.error(f"Error in quick system scan: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/scan/paths', methods=['GET'])
def get_scan_paths():
    """Get recommended scan paths for the current system."""
    try:
        system_paths = get_system_scan_paths()
        
        return jsonify({
            "system_paths": system_paths,
            "platform": platform.system(),
            "recommended_quick_paths": system_paths[:3],
            "all_paths": system_paths
        })
        
    except Exception as e:
        logger.error(f"Error getting scan paths: {e}")
        return jsonify({"error": str(e)}), 500
