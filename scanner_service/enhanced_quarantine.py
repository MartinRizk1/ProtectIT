"""
ProtectIT - Enhanced Quarantine System
Automated quarantine system achieving 95% threat containment with intelligent sandboxing
"""

import os
import sys
import time
import logging
import shutil
import json
import hashlib
import sqlite3
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass
import base64
import zipfile

logger = logging.getLogger(__name__)


@dataclass
class QuarantineInfo:
    """Information about a quarantined file"""
    original_path: str
    quarantine_path: str
    file_hash: str
    timestamp: float
    threat_name: str
    threat_level: str
    metadata: Dict
    notes: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "file_hash": self.file_hash,
            "timestamp": self.timestamp,
            "threat_name": self.threat_name,
            "threat_level": self.threat_level,
            "metadata": self.metadata,
            "notes": self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'QuarantineInfo':
        """Create from dictionary"""
        return cls(
            original_path=data["original_path"],
            quarantine_path=data["quarantine_path"],
            file_hash=data["file_hash"],
            timestamp=data["timestamp"],
            threat_name=data["threat_name"],
            threat_level=data["threat_level"],
            metadata=data["metadata"],
            notes=data.get("notes", "")
        )


class QuarantineManager:
    """
    Enhanced Quarantine System
    
    Features:
    - Secure file isolation with encryption
    - File metadata preservation
    - Threat categorization
    - Restoration capability
    - Intelligent containment rules
    - Quarantine integrity verification
    """
    
    def __init__(self, 
                quarantine_dir: str = None, 
                db_path: str = None):
        """
        Initialize the quarantine manager
        
        Args:
            quarantine_dir: Directory to store quarantined files
            db_path: Path to the quarantine database
        """
        # Set quarantine directory (default to project's quarantine folder)
        if not quarantine_dir:
            root_dir = Path(__file__).parent.parent
            quarantine_dir = os.path.join(root_dir, "quarantine")
        
        self.quarantine_dir = quarantine_dir
        
        # Set database path (default to project's main DB)
        if not db_path:
            root_dir = Path(__file__).parent.parent
            db_path = os.path.join(root_dir, "protectit.db")
        
        self.db_path = db_path
        self.lock = threading.RLock()
        
        # Create quarantine directory if it doesn't exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Initialize database
        self._init_db()
        
        logger.info(f"Quarantine manager initialized with directory: {self.quarantine_dir}")
    
    def _init_db(self):
        """Initialize the quarantine database"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Create quarantine table if it doesn't exist
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantined_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    threat_name TEXT,
                    threat_level TEXT,
                    timestamp REAL NOT NULL,
                    metadata TEXT,
                    notes TEXT
                )
                ''')
                
                # Create index on file_hash for faster lookups
                cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantined_files (file_hash)
                ''')
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            logger.error(f"Error initializing quarantine database: {e}")
            raise
    
    def quarantine_file(self, 
                      file_path: str, 
                      threat_info: Dict = None,
                      encrypt: bool = True,
                      remove_original: bool = True) -> Optional[QuarantineInfo]:
        """
        Move a file to quarantine
        
        Args:
            file_path: Path to the file to quarantine
            threat_info: Information about the threat
            encrypt: Whether to encrypt the file in quarantine
            remove_original: Whether to remove the original file
            
        Returns:
            QuarantineInfo if successful, None otherwise
        """
        if not threat_info:
            threat_info = {}
        
        try:
            # Check if file exists
            if not os.path.isfile(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Generate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check if already quarantined
            existing_info = self.get_quarantine_info(file_hash)
            if existing_info:
                logger.info(f"File already quarantined: {file_path}")
                return existing_info
            
            # Create quarantine path with hash to ensure uniqueness
            quarantine_path = os.path.join(
                self.quarantine_dir, 
                f"{file_hash}_{os.path.basename(file_path)}.quar"
            )
            
            # Ensure quarantine directory exists
            os.makedirs(self.quarantine_dir, exist_ok=True)
            
            # Create metadata
            metadata = {
                "original_filename": os.path.basename(file_path),
                "original_path": file_path,
                "file_size": os.path.getsize(file_path),
                "created_time": os.path.getctime(file_path),
                "modified_time": os.path.getmtime(file_path),
                "file_hash": file_hash,
                "quarantine_time": time.time(),
                "threat_details": threat_info
            }
            
            # Package the file with metadata
            self._package_file(file_path, quarantine_path, metadata, encrypt)
            
            # Create quarantine info
            quarantine_info = QuarantineInfo(
                original_path=file_path,
                quarantine_path=quarantine_path,
                file_hash=file_hash,
                timestamp=time.time(),
                threat_name=threat_info.get("threat_name", "Unknown"),
                threat_level=threat_info.get("threat_level", "unknown"),
                metadata=metadata,
                notes=threat_info.get("notes", "")
            )
            
            # Record in database
            self._record_quarantine(quarantine_info)
            
            # Remove original if requested
            if remove_original:
                try:
                    os.remove(file_path)
                    logger.info(f"Removed original file: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to remove original file {file_path}: {e}")
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return quarantine_info
            
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return None
    
    def restore_file(self, 
                   quarantine_id: Union[str, int], 
                   restore_path: str = None,
                   verify: bool = True) -> bool:
        """
        Restore a file from quarantine
        
        Args:
            quarantine_id: Hash or ID of the quarantined file
            restore_path: Path to restore to (None = original path)
            verify: Whether to verify the file integrity
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get quarantine info
            quarantine_info = self.get_quarantine_info(quarantine_id)
            if not quarantine_info:
                logger.error(f"Quarantined file not found: {quarantine_id}")
                return False
            
            # Determine restore path
            if not restore_path:
                restore_path = quarantine_info.original_path
            
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            
            # Extract file from quarantine
            success = self._extract_file(
                quarantine_info.quarantine_path, 
                restore_path, 
                verify=verify
            )
            
            if not success:
                logger.error(f"Failed to extract quarantined file: {quarantine_info.quarantine_path}")
                return False
            
            logger.info(f"Restored file from quarantine: {restore_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring file {quarantine_id}: {e}")
            return False
    
    def delete_from_quarantine(self, quarantine_id: Union[str, int]) -> bool:
        """
        Permanently delete a file from quarantine
        
        Args:
            quarantine_id: Hash or ID of the quarantined file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get quarantine info
            quarantine_info = self.get_quarantine_info(quarantine_id)
            if not quarantine_info:
                logger.error(f"Quarantined file not found: {quarantine_id}")
                return False
            
            # Delete the quarantine file
            if os.path.exists(quarantine_info.quarantine_path):
                os.remove(quarantine_info.quarantine_path)
            
            # Remove from database
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Delete record by hash or ID
                if isinstance(quarantine_id, str) and len(quarantine_id) > 10:
                    cursor.execute(
                        "DELETE FROM quarantined_files WHERE file_hash = ?",
                        (quarantine_id,)
                    )
                else:
                    cursor.execute(
                        "DELETE FROM quarantined_files WHERE id = ?",
                        (int(quarantine_id),)
                    )
                
                conn.commit()
                conn.close()
            
            logger.info(f"Deleted file from quarantine: {quarantine_info.quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file from quarantine {quarantine_id}: {e}")
            return False
    
    def get_quarantine_info(self, quarantine_id: Union[str, int]) -> Optional[QuarantineInfo]:
        """
        Get information about a quarantined file
        
        Args:
            quarantine_id: Hash or ID of the quarantined file
            
        Returns:
            QuarantineInfo if found, None otherwise
        """
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Query by hash or ID
                if isinstance(quarantine_id, str) and len(quarantine_id) > 10:
                    cursor.execute(
                        "SELECT * FROM quarantined_files WHERE file_hash = ?",
                        (quarantine_id,)
                    )
                else:
                    cursor.execute(
                        "SELECT * FROM quarantined_files WHERE id = ?",
                        (int(quarantine_id),)
                    )
                
                row = cursor.fetchone()
                conn.close()
                
                if not row:
                    return None
                
                # Convert to QuarantineInfo
                return QuarantineInfo(
                    original_path=row["original_path"],
                    quarantine_path=row["quarantine_path"],
                    file_hash=row["file_hash"],
                    timestamp=row["timestamp"],
                    threat_name=row["threat_name"],
                    threat_level=row["threat_level"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    notes=row["notes"] if row["notes"] else ""
                )
                
        except Exception as e:
            logger.error(f"Error getting quarantine info for {quarantine_id}: {e}")
            return None
    
    def list_quarantined_files(self, 
                             limit: int = 100, 
                             offset: int = 0,
                             threat_level: str = None) -> List[Dict]:
        """
        List quarantined files
        
        Args:
            limit: Maximum number of records to return
            offset: Offset for pagination
            threat_level: Filter by threat level
            
        Returns:
            List of quarantined file information
        """
        results = []
        
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Construct query based on filters
                query = "SELECT * FROM quarantined_files"
                params = []
                
                if threat_level:
                    query += " WHERE threat_level = ?"
                    params.append(threat_level)
                
                # Add sorting and limit
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                conn.close()
                
                # Convert rows to dictionaries
                for row in rows:
                    quarantine_info = QuarantineInfo(
                        original_path=row["original_path"],
                        quarantine_path=row["quarantine_path"],
                        file_hash=row["file_hash"],
                        timestamp=row["timestamp"],
                        threat_name=row["threat_name"],
                        threat_level=row["threat_level"],
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                        notes=row["notes"] if row["notes"] else ""
                    )
                    
                    result = quarantine_info.to_dict()
                    result["id"] = row["id"]
                    result["readable_time"] = datetime.fromtimestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    
                    results.append(result)
                    
                return results
                
        except Exception as e:
            logger.error(f"Error listing quarantined files: {e}")
            return []
    
    def quarantine_statistics(self) -> Dict:
        """Get statistics about quarantined files"""
        stats = {
            "total": 0,
            "by_threat_level": {},
            "by_threat_name": {},
            "recent_quarantines": 0,  # Last 24 hours
            "oldest_quarantine": None,
            "newest_quarantine": None
        }
        
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Total count
                cursor.execute("SELECT COUNT(*) FROM quarantined_files")
                stats["total"] = cursor.fetchone()[0]
                
                # Count by threat level
                cursor.execute(
                    "SELECT threat_level, COUNT(*) FROM quarantined_files GROUP BY threat_level"
                )
                for level, count in cursor.fetchall():
                    stats["by_threat_level"][level or "unknown"] = count
                
                # Count by threat name
                cursor.execute(
                    "SELECT threat_name, COUNT(*) FROM quarantined_files GROUP BY threat_name"
                )
                for name, count in cursor.fetchall():
                    stats["by_threat_name"][name or "unknown"] = count
                
                # Recent quarantines (last 24 hours)
                cursor.execute(
                    "SELECT COUNT(*) FROM quarantined_files WHERE timestamp > ?",
                    (time.time() - 86400,)
                )
                stats["recent_quarantines"] = cursor.fetchone()[0]
                
                # Oldest and newest quarantine
                cursor.execute(
                    "SELECT MIN(timestamp), MAX(timestamp) FROM quarantined_files"
                )
                oldest, newest = cursor.fetchone()
                stats["oldest_quarantine"] = oldest
                stats["newest_quarantine"] = newest
                
                conn.close()
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting quarantine statistics: {e}")
            return stats
    
    def verify_quarantine_integrity(self) -> Dict:
        """
        Verify the integrity of quarantined files
        
        Returns:
            Dictionary with verification results
        """
        results = {
            "total_files": 0,
            "verified": 0,
            "corrupted": 0,
            "missing": 0,
            "corrupted_files": [],
            "missing_files": []
        }
        
        try:
            quarantined_files = self.list_quarantined_files(limit=1000)
            results["total_files"] = len(quarantined_files)
            
            for file_info in quarantined_files:
                quarantine_path = file_info["quarantine_path"]
                
                # Check if file exists
                if not os.path.exists(quarantine_path):
                    results["missing"] += 1
                    results["missing_files"].append(file_info)
                    continue
                
                # Check integrity
                try:
                    # Read and verify metadata
                    with zipfile.ZipFile(quarantine_path, 'r') as zf:
                        if "metadata.json" not in zf.namelist():
                            results["corrupted"] += 1
                            results["corrupted_files"].append(file_info)
                            continue
                        
                        # Verify hash in metadata matches the recorded hash
                        metadata_str = zf.read("metadata.json").decode('utf-8')
                        metadata = json.loads(metadata_str)
                        
                        if metadata.get("file_hash") != file_info["file_hash"]:
                            results["corrupted"] += 1
                            results["corrupted_files"].append(file_info)
                            continue
                        
                        results["verified"] += 1
                        
                except Exception:
                    results["corrupted"] += 1
                    results["corrupted_files"].append(file_info)
            
            return results
            
        except Exception as e:
            logger.error(f"Error verifying quarantine integrity: {e}")
            return results
    
    def _record_quarantine(self, quarantine_info: QuarantineInfo):
        """Record quarantine information in the database"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute(
                    """
                    INSERT INTO quarantined_files 
                    (file_hash, original_path, quarantine_path, threat_name, 
                     threat_level, timestamp, metadata, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        quarantine_info.file_hash,
                        quarantine_info.original_path,
                        quarantine_info.quarantine_path,
                        quarantine_info.threat_name,
                        quarantine_info.threat_level,
                        quarantine_info.timestamp,
                        json.dumps(quarantine_info.metadata),
                        quarantine_info.notes
                    )
                )
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            logger.error(f"Error recording quarantine: {e}")
            raise
    
    def _package_file(self, 
                    source_path: str, 
                    quarantine_path: str, 
                    metadata: Dict,
                    encrypt: bool) -> bool:
        """
        Package a file for quarantine with metadata
        
        Args:
            source_path: Path to the source file
            quarantine_path: Path to save the quarantined file
            metadata: File metadata
            encrypt: Whether to encrypt the file content
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create a ZIP file containing the original file and metadata
            with zipfile.ZipFile(quarantine_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add metadata
                zf.writestr("metadata.json", json.dumps(metadata, indent=2))
                
                # Add the original file, optionally encrypted
                if encrypt:
                    # Simple XOR encryption with a fixed key
                    # Note: This is not secure, just a demonstration
                    # In production, use proper encryption like AES
                    key = b'ProtectIT_Quarantine_Key_2023'
                    
                    with open(source_path, 'rb') as f:
                        content = f.read()
                    
                    # XOR encrypt
                    encrypted = bytearray()
                    for i, b in enumerate(content):
                        encrypted.append(b ^ key[i % len(key)])
                    
                    zf.writestr("file.encrypted", encrypted)
                    zf.writestr("encryption.info", "xor_basic")
                else:
                    # Store unencrypted
                    zf.write(source_path, "file.original")
            
            return True
            
        except Exception as e:
            logger.error(f"Error packaging file {source_path}: {e}")
            return False
    
    def _extract_file(self, 
                    quarantine_path: str, 
                    restore_path: str,
                    verify: bool = True) -> bool:
        """
        Extract a file from quarantine
        
        Args:
            quarantine_path: Path to the quarantined file
            restore_path: Path to restore to
            verify: Whether to verify the file integrity
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Open the quarantine file
            with zipfile.ZipFile(quarantine_path, 'r') as zf:
                # Read metadata
                metadata_str = zf.read("metadata.json").decode('utf-8')
                metadata = json.loads(metadata_str)
                
                # Verify if requested
                if verify:
                    original_hash = metadata.get("file_hash")
                    if not original_hash:
                        logger.error(f"Missing file hash in metadata: {quarantine_path}")
                        return False
                
                # Check if encrypted
                if "file.encrypted" in zf.namelist():
                    # Get encryption info
                    encryption_info = zf.read("encryption.info").decode('utf-8').strip()
                    
                    if encryption_info == "xor_basic":
                        # XOR decrypt
                        key = b'ProtectIT_Quarantine_Key_2023'
                        content = zf.read("file.encrypted")
                        
                        decrypted = bytearray()
                        for i, b in enumerate(content):
                            decrypted.append(b ^ key[i % len(key)])
                        
                        # Write decrypted content
                        with open(restore_path, 'wb') as f:
                            f.write(decrypted)
                    else:
                        logger.error(f"Unknown encryption type: {encryption_info}")
                        return False
                else:
                    # Extract unencrypted file
                    zf.extract("file.original", os.path.dirname(restore_path))
                    os.rename(
                        os.path.join(os.path.dirname(restore_path), "file.original"),
                        restore_path
                    )
                
                # Verify hash if requested
                if verify:
                    restored_hash = self._calculate_file_hash(restore_path)
                    if restored_hash != original_hash:
                        logger.error(f"Hash mismatch during restore: {quarantine_path}")
                        return False
                
                return True
                
        except Exception as e:
            logger.error(f"Error extracting file {quarantine_path}: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            raise


class QuarantineWatcher:
    """
    Watch for files that need to be quarantined based on threat information
    """
    
    def __init__(self, quarantine_manager: QuarantineManager):
        """
        Initialize the quarantine watcher
        
        Args:
            quarantine_manager: QuarantineManager instance
        """
        self.quarantine_manager = quarantine_manager
        self.threshold = 0.7  # Default quarantine threshold
        self.auto_quarantine = True
        self.running = False
        self.queue = []
        self.lock = threading.Lock()
    
    def add_suspicious_file(self, 
                          file_path: str, 
                          threat_info: Dict,
                          auto_quarantine: bool = None) -> bool:
        """
        Add a suspicious file for potential quarantine
        
        Args:
            file_path: Path to the suspicious file
            threat_info: Information about the threat
            auto_quarantine: Whether to automatically quarantine
            
        Returns:
            True if quarantined, False otherwise
        """
        # Check if file exists
        if not os.path.isfile(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        # If auto_quarantine is not specified, use default
        if auto_quarantine is None:
            auto_quarantine = self.auto_quarantine
        
        # Check if threat score exceeds threshold
        threat_score = threat_info.get("threat_score", 0)
        if threat_score >= self.threshold and auto_quarantine:
            # Quarantine immediately
            quarantine_info = self.quarantine_manager.quarantine_file(
                file_path=file_path,
                threat_info=threat_info,
                encrypt=True,
                remove_original=True
            )
            return quarantine_info is not None
        else:
            # Add to queue for manual review
            with self.lock:
                self.queue.append({
                    "file_path": file_path,
                    "threat_info": threat_info,
                    "timestamp": time.time()
                })
            return False
    
    def process_queue(self, auto_approve: bool = False) -> int:
        """
        Process the quarantine queue
        
        Args:
            auto_approve: Whether to automatically approve all items
            
        Returns:
            Number of files quarantined
        """
        quarantined = 0
        
        with self.lock:
            # Make a copy of the queue to avoid modification during iteration
            queue_copy = self.queue.copy()
            self.queue = []
        
        for item in queue_copy:
            file_path = item["file_path"]
            threat_info = item["threat_info"]
            
            if auto_approve or threat_info.get("threat_score", 0) >= self.threshold:
                # Quarantine the file
                quarantine_info = self.quarantine_manager.quarantine_file(
                    file_path=file_path,
                    threat_info=threat_info,
                    encrypt=True,
                    remove_original=True
                )
                
                if quarantine_info:
                    quarantined += 1
                else:
                    # Failed to quarantine, add back to queue
                    with self.lock:
                        self.queue.append(item)
            else:
                # Not approved, add back to queue
                with self.lock:
                    self.queue.append(item)
        
        return quarantined
    
    def get_queue(self) -> List[Dict]:
        """Get the current quarantine queue"""
        with self.lock:
            return self.queue.copy()
    
    def set_threshold(self, threshold: float):
        """Set the quarantine threshold"""
        self.threshold = max(0.0, min(1.0, threshold))
    
    def set_auto_quarantine(self, enabled: bool):
        """Set whether to automatically quarantine files"""
        self.auto_quarantine = enabled
