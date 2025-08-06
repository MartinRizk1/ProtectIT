"""
ProtectIT - Malware Detection Engine
Advanced scanning capabilities with ML/static analysis and optional ClamAV integration
"""

import os
import hashlib
import psutil
import time
import asyncio
import shutil
import json
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any, Union
from datetime import datetime
import aiofiles
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
import clamd

# Local imports
import config


class MalwareScanner:
    """Base malware scanner class with shared functionality"""
    
    def __init__(self):
        """Initialize the malware scanner"""
        self.ml_model = None
        self.vectorizer = None
        self.clamd = None
        
        # Initialize ClamAV if configured
        if config.USE_CLAMAV:
            try:
                self.clamd = clamd.ClamdNetworkSocket(
                    host=config.CLAMD_HOST,
                    port=config.CLAMD_PORT
                )
                # Test the connection
                self.clamd.ping()
                print("ClamAV connection established")
            except Exception as e:
                print(f"ClamAV connection failed: {str(e)}")
                self.clamd = None
    
    def initialize_ml_model(self):
        """Initialize or load the machine learning model for malware detection"""
        try:
            # Check if model exists
            if os.path.exists(config.ML_MODEL_PATH):
                print("Loading existing ML model...")
                model_data = joblib.load(config.ML_MODEL_PATH)
                self.ml_model = model_data['model']
                self.vectorizer = model_data['vectorizer']
                print("ML model loaded successfully")
            else:
                print("ML model not found. Using static analysis only.")
                # In a real implementation, we would either:
                # 1. Train a new model with training data
                # 2. Download a pre-trained model
                # For this implementation, we'll create a simple model
                self._create_simple_model()
        except Exception as e:
            print(f"Error initializing ML model: {str(e)}")
            self.ml_model = None
            self.vectorizer = None
    
    def _create_simple_model(self):
        """Create a simple model for demonstration purposes"""
        # This is just a placeholder - in reality, you'd train on real data
        print("Creating a simple demonstration model...")
        
        # Create a simple binary feature vectorizer
        self.vectorizer = CountVectorizer(
            max_features=config.FEATURE_VECTOR_SIZE,
            binary=True,
            ngram_range=(1, 2)
        )
        
        # Simple random forest classifier
        self.ml_model = RandomForestClassifier(
            n_estimators=10,
            max_depth=5,
            random_state=42
        )
        
        # "Train" on some basic patterns
        samples = [
            "cmd.exe /c powershell", 
            "netsh firewall add", 
            "reg add HKLM",
            "normal benign text example",
            "regular application behavior"
        ]
        
        labels = [1, 1, 1, 0, 0]  # 1 for malicious, 0 for benign
        
        # Fit the vectorizer
        features = self.vectorizer.fit_transform(samples)
        
        # Fit the classifier
        self.ml_model.fit(features, labels)
        
        # Save the model
        joblib.dump({
            'model': self.ml_model,
            'vectorizer': self.vectorizer
        }, config.ML_MODEL_PATH)
        
        print("Simple demonstration model created and saved")
    
    async def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            
            async with aiofiles.open(file_path, "rb") as f:
                while chunk := await f.read(65536):
                    hash_sha256.update(chunk)
                    
            return hash_sha256.hexdigest()
        except Exception as e:
            print(f"Error calculating file hash: {str(e)}")
            return "error-hash-calculation-failed"
    
    def check_file_extension(self, file_path: str) -> Optional[str]:
        """Check if the file has a suspicious extension"""
        file_ext = Path(file_path).suffix.lower()
        if file_ext in config.SUSPICIOUS_EXTENSIONS:
            return f"Suspicious file extension: {file_ext}"
        return None
    
    async def check_file_signatures(self, file_path: str) -> list:
        """Check file for suspicious signatures and patterns"""
        threats = []
        try:
            # Read the first part of the file
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read(config.SCAN_CHUNK_SIZE)
            
            # Check for suspicious patterns
            for pattern in config.SUSPICIOUS_PATTERNS:
                if pattern in content:
                    threats.append(f"Suspicious pattern: {pattern.decode('utf-8', errors='ignore')}")
            
            return threats
        except Exception as e:
            print(f"Error checking file signatures: {str(e)}")
            return []
    
    async def analyze_with_ml(self, file_path: str) -> Optional[float]:
        """Analyze file with ML model to predict malware probability"""
        if not self.ml_model or not self.vectorizer:
            return None
            
        try:
            # Extract text features from the file
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read(config.SCAN_CHUNK_SIZE)
            
            # Convert binary content to string for vectorizer
            text = content.decode('utf-8', errors='ignore')
            
            # Transform using vectorizer
            features = self.vectorizer.transform([text])
            
            # Predict probability of being malicious
            probabilities = self.ml_model.predict_proba(features)[0]
            
            # Return probability of malicious class (assuming class 1 is malicious)
            if len(probabilities) >= 2:
                return probabilities[1]
            return 0.0
        except Exception as e:
            print(f"Error analyzing with ML: {str(e)}")
            return None
    
    async def scan_with_clamav(self, file_path: str) -> Optional[str]:
        """Scan file with ClamAV if available"""
        if not self.clamd or not config.USE_CLAMAV:
            return None
            
        try:
            result = self.clamd.scan(file_path)
            for item in result.values():
                status = item[0]
                if status == "FOUND":
                    return item[1]  # Return virus name
            return None
        except Exception as e:
            print(f"ClamAV scan error: {str(e)}")
            return None
    
    def get_risk_level(self, score: float) -> str:
        """Convert a risk score to a risk level"""
        if score >= config.RISK_THRESHOLD_HIGH:
            return "CRITICAL"
        elif score >= config.RISK_THRESHOLD_MEDIUM:
            return "HIGH"
        elif score >= config.RISK_THRESHOLD_LOW:
            return "MEDIUM"
        else:
            return "LOW"


class FileScanner(MalwareScanner):
    """Scanner for individual files"""
    
    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
    
    async def scan_file(self) -> dict:
        """Scan a single file for malware"""
        start_time = time.time()
        threats = []
        threat_count = 0
        risk_score = 0.0
        risk_level = "LOW"
        
        try:
            # Basic check - does the file exist?
            if not os.path.exists(self.file_path):
                return {
                    "status": "error",
                    "error": "File not found",
                    "file_path": self.file_path,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Calculate file hash
            file_hash = await self.calculate_file_hash(self.file_path)
            
            # Check file extension
            ext_threat = self.check_file_extension(self.file_path)
            if ext_threat:
                threats.append({
                    "type": "suspicious_extension",
                    "name": ext_threat,
                    "description": "File has a potentially dangerous extension",
                    "risk_level": "MEDIUM"
                })
                risk_score += 0.3
                threat_count += 1
            
            # Check file signatures
            sig_threats = await self.check_file_signatures(self.file_path)
            for threat in sig_threats:
                threats.append({
                    "type": "suspicious_pattern",
                    "name": threat,
                    "description": "File contains suspicious code patterns",
                    "risk_level": "HIGH"
                })
                risk_score += 0.4
                threat_count += 1
            
            # ML analysis if available
            ml_score = await self.analyze_with_ml(self.file_path)
            if ml_score and ml_score > config.RISK_THRESHOLD_LOW:
                threats.append({
                    "type": "ml_detection",
                    "name": "ML Detection",
                    "description": f"Machine learning model flagged this file (score: {ml_score:.2f})",
                    "risk_level": self.get_risk_level(ml_score)
                })
                risk_score = max(risk_score, ml_score)
                threat_count += 1
            
            # ClamAV scan if available
            clam_result = await self.scan_with_clamav(self.file_path)
            if clam_result:
                threats.append({
                    "type": "virus",
                    "name": clam_result,
                    "description": f"Known virus signature detected: {clam_result}",
                    "risk_level": "CRITICAL"
                })
                risk_score = 1.0
                threat_count += 1
            
            # Calculate overall risk level
            risk_level = self.get_risk_level(risk_score)
            
            # Prepare and return the result
            result = {
                "status": "completed",
                "file_path": self.file_path,
                "file_hash": file_hash,
                "file_size": os.path.getsize(self.file_path),
                "file_type": Path(self.file_path).suffix.lower(),
                "scan_duration": time.time() - start_time,
                "threats_found": threat_count,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "threats": threats,
                "timestamp": datetime.now().isoformat()
            }
            
            return result
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "file_path": self.file_path,
                "timestamp": datetime.now().isoformat()
            }


class DirectoryScanner(MalwareScanner):
    """Scanner for directories"""
    
    def __init__(self, directory_path: str, recursive: bool = True):
        super().__init__()
        self.directory_path = directory_path
        self.recursive = recursive
    
    def count_files(self) -> int:
        """Count files in the directory for progress tracking"""
        if not self.recursive:
            return sum(1 for item in os.listdir(self.directory_path) 
                     if os.path.isfile(os.path.join(self.directory_path, item)))
        
        file_count = 0
        for root, _, files in os.walk(self.directory_path):
            file_count += len(files)
        return file_count
    
    async def scan_directory(self, progress_callback: Optional[Callable] = None) -> dict:
        """Scan a directory for malware"""
        start_time = time.time()
        
        try:
            if not os.path.exists(self.directory_path):
                return {
                    "status": "error",
                    "error": "Directory not found",
                    "directory_path": self.directory_path,
                    "timestamp": datetime.now().isoformat()
                }
            
            if not os.path.isdir(self.directory_path):
                return {
                    "status": "error",
                    "error": "Path is not a directory",
                    "directory_path": self.directory_path,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Results
            threats = []
            scanned_files = 0
            total_files = self.count_files()
            
            # Function to scan a single file
            async def scan_single_file(file_path):
                nonlocal scanned_files, threats
                scanned_files += 1
                
                # Skip files that are too large
                if os.path.getsize(file_path) > config.MAX_FILE_SIZE:
                    if progress_callback:
                        progress = min(int((scanned_files / max(total_files, 1)) * 100), 100)
                        await progress_callback(progress, file_path)
                    return
                
                file_scanner = FileScanner(file_path)
                scan_result = await file_scanner.scan_file()
                
                # Add threats to the list
                if scan_result["threats_found"] > 0:
                    for threat in scan_result["threats"]:
                        threat["file_path"] = file_path
                        threat["hash"] = scan_result["file_hash"]
                        threats.append(threat)
                    
                    # Call progress callback more frequently for threat findings
                    if progress_callback:
                        progress = min(int((scanned_files / max(total_files, 1)) * 100), 100)
                        await progress_callback(progress, file_path)
                # Less frequent updates for clean files
                elif progress_callback and scanned_files % 10 == 0:
                    progress = min(int((scanned_files / max(total_files, 1)) * 100), 100)
                    await progress_callback(progress, file_path)
            
            # Scan files
            tasks = []
            
            # Non-recursive scan
            if not self.recursive:
                for item in os.listdir(self.directory_path):
                    file_path = os.path.join(self.directory_path, item)
                    if os.path.isfile(file_path):
                        tasks.append(scan_single_file(file_path))
            # Recursive scan
            else:
                for root, _, files in os.walk(self.directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        tasks.append(scan_single_file(file_path))
            
            # Run all file scans (with concurrency limits)
            # Process files in chunks to avoid too many concurrent operations
            for i in range(0, len(tasks), config.MAX_SCAN_THREADS):
                chunk = tasks[i:i + config.MAX_SCAN_THREADS]
                await asyncio.gather(*chunk)
            
            # Calculate summaries
            threat_types = {}
            risk_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            
            for threat in threats:
                threat_type = threat.get("type", "unknown")
                risk_level = threat.get("risk_level", "LOW")
                
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
            
            # Prepare final result
            result = {
                "status": "completed",
                "directory_path": self.directory_path,
                "recursive": self.recursive,
                "scan_duration": time.time() - start_time,
                "files_scanned": scanned_files,
                "threats_found": len(threats),
                "threats": threats,
                "summary": {
                    "threat_types": threat_types,
                    "risk_levels": risk_levels
                },
                "timestamp": datetime.now().isoformat()
            }
            
            return result
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "directory_path": self.directory_path,
                "timestamp": datetime.now().isoformat()
            }


class ProcessScanner(MalwareScanner):
    """Scanner for running processes"""
    
    def __init__(self):
        super().__init__()
        self.suspicious_process_names = {
            'keylogger', 'rootkit', 'backdoor', 'trojan', 'worm', 'virus',
            'malware', 'spyware', 'adware', 'ransomware', 'miner', 'botnet'
        }
        
        self.suspicious_paths = {
            '/tmp/', '/var/tmp/', '%TEMP%', '%APPDATA%', 
            '/Library/LaunchAgents/', '/Library/LaunchDaemons/',
        }
    
    async def scan_processes(self) -> dict:
        """Scan running processes for suspicious activity"""
        start_time = time.time()
        suspicious_processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    proc_info = proc.info
                    is_suspicious = False
                    threat = {
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "user": proc_info.get('username', 'unknown'),
                        "path": proc_info.get('exe', ''),
                        "command": ' '.join(proc_info.get('cmdline', [])) if proc_info.get('cmdline') else '',
                        "reasons": []
                    }
                    
                    # Check suspicious process name
                    if proc_info['name']:
                        proc_name = proc_info['name'].lower()
                        for suspicious in self.suspicious_process_names:
                            if suspicious in proc_name:
                                threat["reasons"].append(f"Suspicious process name: {suspicious}")
                                is_suspicious = True
                    
                    # Check suspicious paths
                    if proc_info['exe']:
                        for path in self.suspicious_paths:
                            if path in proc_info['exe']:
                                threat["reasons"].append(f"Running from suspicious location: {path}")
                                is_suspicious = True
                    
                    # Check command line for suspicious patterns
                    if proc_info.get('cmdline'):
                        cmdline = ' '.join(proc_info['cmdline']).lower()
                        for pattern in ['netsh', 'reg add', 'taskkill', 'runas', 'regedit', 'powershell -exec bypass']:
                            if pattern in cmdline:
                                threat["reasons"].append(f"Suspicious command line: {pattern}")
                                is_suspicious = True
                    
                    # If process was marked as suspicious, add to results
                    if is_suspicious:
                        threat["risk_level"] = "HIGH"
                        suspicious_processes.append(threat)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Prepare result
            result = {
                "status": "completed",
                "scan_duration": time.time() - start_time,
                "processes_scanned": len(list(psutil.process_iter())),
                "suspicious_processes": len(suspicious_processes),
                "threats": suspicious_processes,
                "timestamp": datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }


class SystemScanner(MalwareScanner):
    """Scanner for full system scans"""
    
    def __init__(self, include_processes=True, include_startup=True, include_common_dirs=True):
        super().__init__()
        self.include_processes = include_processes
        self.include_startup = include_startup
        self.include_common_dirs = include_common_dirs
        
        # Define common directories to scan
        self.common_directories = []
        
        # Detect OS and set appropriate directories
        if os.name == "posix":  # macOS or Linux
            if os.path.exists("/Users"):  # macOS
                self.common_directories = [
                    "/Applications",
                    "/Library/LaunchAgents",
                    "/Library/LaunchDaemons",
                    "/Library/StartupItems",
                    os.path.expanduser("~/Library/LaunchAgents"),
                    os.path.expanduser("~/Downloads"),
                    "/tmp"
                ]
            else:  # Linux
                self.common_directories = [
                    "/bin",
                    "/usr/bin",
                    "/tmp",
                    "/var/tmp",
                    "/etc/cron.d",
                    "/etc/init.d",
                    os.path.expanduser("~/Downloads")
                ]
        else:  # Windows
            self.common_directories = [
                "C:\\Windows\\System32",
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\AppData\\Local\\Temp"),
                os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            ]
    
    async def scan_system(self, progress_callback: Optional[Callable] = None) -> dict:
        """Perform a full system scan"""
        start_time = time.time()
        results = {
            "status": "completed",
            "scan_sections": [],
            "threats_found": 0,
            "threats": [],
            "summary": {},
            "scan_duration": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # 1. Process scanning
            if self.include_processes:
                if progress_callback:
                    await progress_callback(10, "Scanning running processes")
                    
                process_scanner = ProcessScanner()
                process_results = await process_scanner.scan_processes()
                
                if process_results["status"] == "completed":
                    results["scan_sections"].append({
                        "name": "processes",
                        "threats_found": process_results["suspicious_processes"]
                    })
                    
                    # Add process threats to overall threats
                    for threat in process_results["threats"]:
                        threat["type"] = "suspicious_process"
                        results["threats"].append(threat)
                        results["threats_found"] += 1
            
            # 2. Startup items scanning
            if self.include_startup:
                if progress_callback:
                    await progress_callback(20, "Scanning startup items")
                
                # Scan startup directories based on OS
                if os.name == "posix":  # macOS or Linux
                    startup_dirs = []
                    
                    if os.path.exists("/Library/LaunchAgents"):  # macOS
                        startup_dirs = [
                            "/Library/LaunchAgents",
                            "/Library/LaunchDaemons",
                            "/Library/StartupItems",
                            os.path.expanduser("~/Library/LaunchAgents")
                        ]
                    else:  # Linux
                        startup_dirs = [
                            "/etc/init.d",
                            "/etc/cron.d",
                            os.path.expanduser("~/.config/autostart")
                        ]
                    
                    for startup_dir in startup_dirs:
                        if os.path.exists(startup_dir):
                            if progress_callback:
                                await progress_callback(25, f"Scanning {startup_dir}")
                            
                            dir_scanner = DirectoryScanner(startup_dir)
                            dir_results = await dir_scanner.scan_directory()
                            
                            if dir_results["status"] == "completed":
                                results["scan_sections"].append({
                                    "name": f"startup_dir_{Path(startup_dir).name}",
                                    "path": startup_dir,
                                    "threats_found": dir_results["threats_found"]
                                })
                                
                                # Add directory threats to overall threats
                                for threat in dir_results["threats"]:
                                    results["threats"].append(threat)
                                    results["threats_found"] += 1
                
                else:  # Windows
                    startup_dirs = [
                        os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
                    ]
                    
                    for startup_dir in startup_dirs:
                        if os.path.exists(startup_dir):
                            if progress_callback:
                                await progress_callback(25, f"Scanning {startup_dir}")
                            
                            dir_scanner = DirectoryScanner(startup_dir)
                            dir_results = await dir_scanner.scan_directory()
                            
                            if dir_results["status"] == "completed":
                                results["scan_sections"].append({
                                    "name": f"startup_dir_{Path(startup_dir).name}",
                                    "path": startup_dir,
                                    "threats_found": dir_results["threats_found"]
                                })
                                
                                # Add directory threats to overall threats
                                for threat in dir_results["threats"]:
                                    results["threats"].append(threat)
                                    results["threats_found"] += 1
            
            # 3. Common directories scanning
            if self.include_common_dirs:
                progress_base = 30
                progress_step = 65 / max(len(self.common_directories), 1)
                
                for i, directory in enumerate(self.common_directories):
                    if os.path.exists(directory):
                        current_progress = progress_base + (i * progress_step)
                        if progress_callback:
                            await progress_callback(current_progress, f"Scanning {directory}")
                        
                        dir_scanner = DirectoryScanner(directory)
                        dir_results = await dir_scanner.scan_directory()
                        
                        if dir_results["status"] == "completed":
                            results["scan_sections"].append({
                                "name": f"directory_{Path(directory).name}",
                                "path": directory,
                                "threats_found": dir_results["threats_found"]
                            })
                            
                            # Add directory threats to overall threats
                            for threat in dir_results["threats"]:
                                results["threats"].append(threat)
                                results["threats_found"] += 1
            
            # Calculate final summary
            threat_types = {}
            risk_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            
            for threat in results["threats"]:
                threat_type = threat.get("type", "unknown")
                risk_level = threat.get("risk_level", "LOW")
                
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
            
            results["summary"] = {
                "threat_types": threat_types,
                "risk_levels": risk_levels,
                "total_threats": results["threats_found"]
            }
            
            # Final progress update
            if progress_callback:
                await progress_callback(100, "System scan completed")
            
            # Set scan duration
            results["scan_duration"] = time.time() - start_time
            
            return results
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "scan_duration": time.time() - start_time,
                "timestamp": datetime.now().isoformat()
            }
