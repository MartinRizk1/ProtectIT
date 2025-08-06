"""
Advanced Quarantine System for ProtectIT
Safely isolates and manages detected threats
"""

import os
import shutil
import json
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
import base64
from cryptography.fernet import Fernet

class QuarantineManager:
    """Manages quarantined files and threats"""
    
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(exist_ok=True)
        
        # Initialize quarantine database
        self.db_path = self.quarantine_dir / "quarantine.db"
        self.init_quarantine_db()
        
        # Generate or load encryption key
        self.key_file = self.quarantine_dir / ".qkey"
        self.encryption_key = self._get_or_create_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def _get_or_create_key(self):
        """Get existing encryption key or create new one"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Hide the key file (macOS/Linux)
            os.system(f"chflags hidden {self.key_file}")
            return key
    
    def init_quarantine_db(self):
        """Initialize quarantine database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS quarantined_files
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      original_path TEXT,
                      quarantine_path TEXT,
                      file_hash TEXT,
                      threat_name TEXT,
                      detection_date TEXT,
                      file_size INTEGER,
                      status TEXT,
                      metadata TEXT)''')
        
        conn.commit()
        conn.close()
    
    def quarantine_file(self, file_path, threat_info):
        """Move a file to quarantine with encryption"""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Create quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{file_hash[:8]}.quar"
            quarantine_path = self.quarantine_dir / quarantine_filename
            
            # Read and encrypt file
            with open(file_path, 'rb') as original_file:
                file_data = original_file.read()
                encrypted_data = self.cipher_suite.encrypt(file_data)
            
            # Write encrypted file to quarantine
            with open(quarantine_path, 'wb') as quarantine_file:
                quarantine_file.write(encrypted_data)
            
            # Store metadata
            metadata = {
                'original_name': os.path.basename(file_path),
                'original_size': file_size,
                'quarantine_date': datetime.now().isoformat(),
                'threat_details': threat_info,
                'encrypted': True
            }
            
            # Add to database
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''INSERT INTO quarantined_files 
                        (original_path, quarantine_path, file_hash, threat_name, 
                         detection_date, file_size, status, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (file_path, str(quarantine_path), file_hash, 
                      threat_info.get('name', 'Unknown'), 
                      datetime.now().isoformat(), file_size, 'quarantined',
                      json.dumps(metadata)))
            
            conn.commit()
            conn.close()
            
            # Remove original file
            try:
                os.remove(file_path)
                return True, f"File quarantined successfully: {quarantine_filename}"
            except Exception as e:
                # If we can't remove original, at least we have it quarantined
                return True, f"File quarantined (original file couldn't be removed): {str(e)}"
                
        except Exception as e:
            return False, f"Quarantine failed: {str(e)}"
    
    def list_quarantined_files(self):
        """List all quarantined files"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT * FROM quarantined_files ORDER BY detection_date DESC''')
        columns = [description[0] for description in c.description]
        
        results = []
        for row in c.fetchall():
            file_info = dict(zip(columns, row))
            # Parse metadata
            if file_info['metadata']:
                try:
                    file_info['metadata'] = json.loads(file_info['metadata'])
                except:
                    file_info['metadata'] = {}
            results.append(file_info)
        
        conn.close()
        return results
    
    def restore_file(self, quarantine_id, restore_path=None):
        """Restore a quarantined file"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''SELECT * FROM quarantined_files WHERE id = ?''', (quarantine_id,))
            file_record = c.fetchone()
            
            if not file_record:
                return False, "Quarantined file not found"
            
            # Get file info
            original_path = file_record[1]
            quarantine_path = file_record[2]
            
            if restore_path is None:
                restore_path = original_path
            
            # Read and decrypt quarantined file
            with open(quarantine_path, 'rb') as quarantine_file:
                encrypted_data = quarantine_file.read()
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            # Create restore directory if needed
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            
            # Write restored file
            with open(restore_path, 'wb') as restored_file:
                restored_file.write(decrypted_data)
            
            # Update database status
            c.execute('''UPDATE quarantined_files 
                        SET status = 'restored' 
                        WHERE id = ?''', (quarantine_id,))
            
            conn.commit()
            conn.close()
            
            return True, f"File restored to: {restore_path}"
            
        except Exception as e:
            return False, f"Restore failed: {str(e)}"
    
    def delete_quarantined_file(self, quarantine_id):
        """Permanently delete a quarantined file"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''SELECT quarantine_path FROM quarantined_files WHERE id = ?''', 
                     (quarantine_id,))
            result = c.fetchone()
            
            if not result:
                return False, "Quarantined file not found"
            
            quarantine_path = result[0]
            
            # Delete physical file
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            
            # Remove from database
            c.execute('''DELETE FROM quarantined_files WHERE id = ?''', (quarantine_id,))
            
            conn.commit()
            conn.close()
            
            return True, "Quarantined file permanently deleted"
            
        except Exception as e:
            return False, f"Deletion failed: {str(e)}"
    
    def get_quarantine_stats(self):
        """Get quarantine statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Total quarantined files
        c.execute('SELECT COUNT(*) FROM quarantined_files WHERE status = "quarantined"')
        total_quarantined = c.fetchone()[0]
        
        # Total restored files
        c.execute('SELECT COUNT(*) FROM quarantined_files WHERE status = "restored"')
        total_restored = c.fetchone()[0]
        
        # Total size of quarantined files
        c.execute('SELECT SUM(file_size) FROM quarantined_files WHERE status = "quarantined"')
        total_size = c.fetchone()[0] or 0
        
        # Threat types breakdown
        c.execute('''SELECT threat_name, COUNT(*) 
                     FROM quarantined_files 
                     WHERE status = "quarantined" 
                     GROUP BY threat_name''')
        threat_breakdown = dict(c.fetchall())
        
        conn.close()
        
        return {
            'total_quarantined': total_quarantined,
            'total_restored': total_restored,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'threat_breakdown': threat_breakdown,
            'quarantine_directory': str(self.quarantine_dir)
        }
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def cleanup_old_quarantine(self, days_old=30):
        """Clean up quarantine files older than specified days"""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Find old quarantined files
        c.execute('''SELECT id, quarantine_path FROM quarantined_files 
                     WHERE detection_date < ? AND status = "quarantined"''',
                 (cutoff_date.isoformat(),))
        
        old_files = c.fetchall()
        cleaned_count = 0
        
        for file_id, quarantine_path in old_files:
            try:
                # Delete physical file
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                
                # Remove from database
                c.execute('DELETE FROM quarantined_files WHERE id = ?', (file_id,))
                cleaned_count += 1
                
            except Exception as e:
                print(f"Error cleaning up {quarantine_path}: {e}")
        
        conn.commit()
        conn.close()
        
        return cleaned_count
