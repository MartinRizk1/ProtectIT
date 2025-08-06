"""
Advanced malware detection utilities
"""

import os
import re
import hashlib
import sqlite3
from datetime import datetime
import json

class ThreatDatabase:
    """Manages threat signatures and known malware hashes"""
    
    def __init__(self, db_path='threats.db'):
        self.db_path = db_path
        self.init_threat_db()
    
    def init_threat_db(self):
        """Initialize threat database with known signatures"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Known malware hashes table
        c.execute('''CREATE TABLE IF NOT EXISTS malware_hashes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      hash_value TEXT UNIQUE,
                      malware_name TEXT,
                      threat_type TEXT,
                      risk_level TEXT,
                      added_date TEXT)''')
        
        # Suspicious file patterns table
        c.execute('''CREATE TABLE IF NOT EXISTS file_patterns
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      pattern TEXT,
                      description TEXT,
                      risk_level TEXT)''')
        
        # Network indicators table
        c.execute('''CREATE TABLE IF NOT EXISTS network_indicators
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      indicator_type TEXT,
                      indicator_value TEXT,
                      description TEXT,
                      risk_level TEXT)''')
        
        # Populate with sample data
        self.populate_sample_threats(c)
        
        conn.commit()
        conn.close()
    
    def populate_sample_threats(self, cursor):
        """Add sample threat data"""
        # Sample malicious file hashes (these are fictional for demo)
        sample_hashes = [
            ('a' * 64, 'TrojanDropper.Generic', 'Trojan', 'HIGH'),
            ('b' * 64, 'Backdoor.RemoteAccess', 'Backdoor', 'CRITICAL'),
            ('c' * 64, 'Worm.NetworkSpread', 'Worm', 'HIGH'),
            ('d' * 64, 'Keylogger.StealInfo', 'Spyware', 'MEDIUM'),
            ('e' * 64, 'Ransomware.FileEncrypt', 'Ransomware', 'CRITICAL')
        ]
        
        for hash_val, name, threat_type, risk in sample_hashes:
            try:
                cursor.execute('''INSERT OR IGNORE INTO malware_hashes 
                                 (hash_value, malware_name, threat_type, risk_level, added_date)
                                 VALUES (?, ?, ?, ?, ?)''',
                              (hash_val, name, threat_type, risk, datetime.now().isoformat()))
            except:
                pass
        
        # Sample suspicious patterns
        patterns = [
            (r'.*\.exe\..*', 'Double extension executable', 'MEDIUM'),
            (r'.*temp.*\.exe', 'Executable in temp directory', 'HIGH'),
            (r'.*\.(scr|pif|com|bat|cmd)$', 'Potentially dangerous file type', 'MEDIUM'),
            (r'.*svchost.*\.exe', 'Suspicious svchost process', 'HIGH'),
            (r'.*\.(vbs|js|wsf)$', 'Script file', 'LOW')
        ]
        
        for pattern, desc, risk in patterns:
            try:
                cursor.execute('''INSERT OR IGNORE INTO file_patterns 
                                 (pattern, description, risk_level)
                                 VALUES (?, ?, ?)''',
                              (pattern, desc, risk))
            except:
                pass
    
    def check_hash(self, file_hash):
        """Check if file hash matches known malware"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT malware_name, threat_type, risk_level 
                     FROM malware_hashes WHERE hash_value = ?''', (file_hash,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return {
                'name': result[0],
                'type': result[1],
                'risk': result[2],
                'found': True
            }
        return {'found': False}
    
    def check_file_pattern(self, file_path):
        """Check file against suspicious patterns"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT pattern, description, risk_level FROM file_patterns')
        patterns = c.fetchall()
        conn.close()
        
        matches = []
        for pattern, desc, risk in patterns:
            if re.match(pattern, file_path.lower()):
                matches.append({
                    'pattern': pattern,
                    'description': desc,
                    'risk_level': risk
                })
        
        return matches

class HeuristicAnalyzer:
    """Performs heuristic analysis on files"""
    
    def __init__(self):
        self.suspicious_strings = [
            b'CreateRemoteThread',
            b'WriteProcessMemory',
            b'VirtualAllocEx',
            b'SetWindowsHookEx',
            b'GetProcAddress',
            b'LoadLibrary',
            b'ShellExecute',
            b'WinExec',
            b'CreateProcess',
            b'RegCreateKey',
            b'RegSetValue',
            b'CryptEncrypt',
            b'CryptDecrypt'
        ]
        
        self.packer_signatures = [
            b'UPX',
            b'FSG',
            b'PECompact',
            b'Themida',
            b'VMProtect'
        ]
    
    def analyze_pe_file(self, file_path):
        """Analyze PE (Windows executable) files"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            analysis_result = {
                'suspicious_apis': [],
                'packed': False,
                'entropy_high': False,
                'risk_score': 0
            }
            
            # Check for suspicious API calls
            for api in self.suspicious_strings:
                if api in data:
                    analysis_result['suspicious_apis'].append(api.decode('utf-8', errors='ignore'))
                    analysis_result['risk_score'] += 10
            
            # Check for packers
            for packer in self.packer_signatures:
                if packer in data:
                    analysis_result['packed'] = True
                    analysis_result['risk_score'] += 20
                    break
            
            # Simple entropy check (high entropy might indicate encryption/packing)
            entropy = self.calculate_entropy(data[:1024])  # Check first 1KB
            if entropy > 7.0:
                analysis_result['entropy_high'] = True
                analysis_result['risk_score'] += 15
            
            return analysis_result
            
        except Exception as e:
            return {'error': str(e)}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        import math
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    
    def analyze_script_file(self, file_path):
        """Analyze script files (JS, VBS, PS1, etc.)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            suspicious_patterns = [
                r'eval\s*\(',
                r'document\.write',
                r'shell\.run',
                r'wscript\.shell',
                r'activexobject',
                r'downloadfile',
                r'invoke-expression',
                r'base64',
                r'fromcharcode'
            ]
            
            analysis_result = {
                'suspicious_patterns': [],
                'obfuscated': False,
                'risk_score': 0
            }
            
            content_lower = content.lower()
            
            for pattern in suspicious_patterns:
                if re.search(pattern, content_lower):
                    analysis_result['suspicious_patterns'].append(pattern)
                    analysis_result['risk_score'] += 15
            
            # Check for obfuscation indicators
            if len(content) > 1000:
                # Check for excessive string concatenation or encoding
                if content.count('+') > 50 or content.count('\\x') > 10:
                    analysis_result['obfuscated'] = True
                    analysis_result['risk_score'] += 25
            
            return analysis_result
            
        except Exception as e:
            return {'error': str(e)}

class SystemMonitor:
    """Monitors system for suspicious activities"""
    
    def __init__(self):
        self.baseline_processes = set()
        self.suspicious_network_connections = []
    
    def establish_baseline(self):
        """Establish baseline of normal system processes"""
        import psutil
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.baseline_processes.add(proc.info['name'])
            except:
                continue
    
    def detect_new_processes(self):
        """Detect processes that weren't in baseline"""
        import psutil
        
        current_processes = set()
        new_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                proc_info = proc.info
                current_processes.add(proc_info['name'])
                
                if proc_info['name'] not in self.baseline_processes:
                    new_processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'create_time': proc_info['create_time']
                    })
            except:
                continue
        
        return new_processes
    
    def monitor_network_connections(self):
        """Monitor for suspicious network connections"""
        import psutil
        
        suspicious_connections = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Check for connections to suspicious ports or IPs
                if conn.raddr:
                    # Common malware communication ports
                    suspicious_ports = {6667, 6668, 6669, 7000, 31337, 12345, 1234}
                    
                    if conn.raddr.port in suspicious_ports:
                        suspicious_connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'pid': conn.pid,
                            'reason': f'Connection to suspicious port {conn.raddr.port}'
                        })
        
        except Exception as e:
            pass
        
        return suspicious_connections

# Export classes for use in main application
__all__ = ['ThreatDatabase', 'HeuristicAnalyzer', 'SystemMonitor']
