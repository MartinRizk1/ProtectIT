#!/usr/bin/env python3
"""
ProtectIT Network Monitor
Real-time network activity monitoring and threat detection
"""

import os
import time
import threading
import logging
import socket
import struct
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import subprocess
import re
import ipaddress
import psutil

logger = logging.getLogger(__name__)


@dataclass
class NetworkConnection:
    """Information about a network connection"""
    pid: int
    process_name: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    family: str
    type: str
    timestamp: datetime


@dataclass
class NetworkTraffic:
    """Network traffic statistics"""
    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errors_in: int
    errors_out: int
    drops_in: int
    drops_out: int
    timestamp: datetime


@dataclass
class SuspiciousActivity:
    """Suspicious network activity detected"""
    activity_type: str
    severity: str
    description: str
    source_ip: str
    destination_ip: str
    port: int
    process_name: str
    pid: int
    timestamp: datetime
    evidence: Dict


class ThreatIntelligence:
    """Threat intelligence database for known malicious IPs and domains"""
    
    def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.suspicious_ports: Set[int] = {
            # Common malware C&C ports
            1337, 31337, 4444, 5555, 6666, 7777, 8080, 8888, 9999,
            # Trojan ports
            12345, 54321, 20034, 9872, 10067, 10167,
            # Botnet ports
            6667, 6697, 1234, 27374, 30029, 31320
        }
        self.known_miners = {
            'stratum+tcp', 'mining', 'pool', 'xmr', 'eth', 'btc'
        }
        
        # Load threat feeds
        self._load_threat_feeds()
    
    def _load_threat_feeds(self):
        """Load threat intelligence from various sources"""
        try:
            # Add some known malicious IPs (example)
            known_bad_ips = [
                "185.220.100.240", "185.220.100.241", "185.220.100.242",
                "185.220.101.1", "185.220.101.2", "185.220.101.3",
                "198.96.155.3", "198.96.155.4", "198.96.155.5"
            ]
            self.malicious_ips.update(known_bad_ips)
            
            # Add known malicious domains
            known_bad_domains = [
                "malware.com", "phishing.net", "badactor.org",
                "cryptominer.biz", "botnet.info"
            ]
            self.malicious_domains.update(known_bad_domains)
            
            logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs and "
                       f"{len(self.malicious_domains)} malicious domains")
            
        except Exception as e:
            logger.error(f"Error loading threat feeds: {e}")
    
    def is_malicious_ip(self, ip: str) -> bool:
        """Check if IP is known to be malicious"""
        return ip in self.malicious_ips
    
    def is_malicious_domain(self, domain: str) -> bool:
        """Check if domain is known to be malicious"""
        return any(bad_domain in domain.lower() for bad_domain in self.malicious_domains)
    
    def is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly used by malware"""
        return port in self.suspicious_ports


class NetworkMonitor:
    """Advanced network monitoring and threat detection"""
    
    def __init__(self, update_interval: float = 2.0, history_size: int = 1000):
        self.update_interval = update_interval
        self.history_size = history_size
        self.running = False
        self.monitor_thread = None
        
        # Data storage
        self.connections: List[NetworkConnection] = []
        self.traffic_history: List[NetworkTraffic] = []
        self.suspicious_activities: List[SuspiciousActivity] = []
        self.data_lock = threading.Lock()
        
        # Threat intelligence
        self.threat_intel = ThreatIntelligence()
        
        # Monitoring state
        self.baseline_traffic = {}
        self.connection_tracking = {}
        self.alert_callbacks = []
        
        # Detection thresholds
        self.thresholds = {
            'high_traffic_threshold': 10 * 1024 * 1024,  # 10MB
            'connection_count_threshold': 50,
            'unusual_port_threshold': 10,
            'data_exfiltration_threshold': 100 * 1024 * 1024  # 100MB
        }
        
        logger.info("NetworkMonitor initialized")
    
    def add_alert_callback(self, callback):
        """Add callback for security alerts"""
        self.alert_callbacks.append(callback)
    
    def get_network_connections(self) -> List[NetworkConnection]:
        """Get current network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Get process info
                    process = psutil.Process(conn.pid) if conn.pid else None
                    process_name = process.name() if process else "Unknown"
                    
                    # Parse addresses
                    local_addr = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_addr = conn.raddr.ip if conn.raddr else "0.0.0.0"
                    remote_port = conn.raddr.port if conn.raddr else 0
                    
                    connection = NetworkConnection(
                        pid=conn.pid or 0,
                        process_name=process_name,
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr,
                        remote_port=remote_port,
                        status=conn.status,
                        family=conn.family.name,
                        type=conn.type.name,
                        timestamp=datetime.now()
                    )
                    
                    connections.append(connection)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"Error getting network connections: {e}")
        
        return connections
    
    def get_network_traffic(self) -> List[NetworkTraffic]:
        """Get network traffic statistics for all interfaces"""
        traffic_stats = []
        
        try:
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                traffic = NetworkTraffic(
                    interface=interface,
                    bytes_sent=stats.bytes_sent,
                    bytes_recv=stats.bytes_recv,
                    packets_sent=stats.packets_sent,
                    packets_recv=stats.packets_recv,
                    errors_in=stats.errin,
                    errors_out=stats.errout,
                    drops_in=stats.dropin,
                    drops_out=stats.dropout,
                    timestamp=datetime.now()
                )
                traffic_stats.append(traffic)
                
        except Exception as e:
            logger.error(f"Error getting network traffic: {e}")
        
        return traffic_stats
    
    def detect_suspicious_connections(self, connections: List[NetworkConnection]) -> List[SuspiciousActivity]:
        """Detect suspicious network connections"""
        suspicious = []
        
        for conn in connections:
            try:
                # Check for connections to known malicious IPs
                if self.threat_intel.is_malicious_ip(conn.remote_address):
                    suspicious.append(SuspiciousActivity(
                        activity_type="malicious_ip_connection",
                        severity="high",
                        description=f"Connection to known malicious IP {conn.remote_address}",
                        source_ip=conn.local_address,
                        destination_ip=conn.remote_address,
                        port=conn.remote_port,
                        process_name=conn.process_name,
                        pid=conn.pid,
                        timestamp=conn.timestamp,
                        evidence={"connection_status": conn.status, "family": conn.family}
                    ))
                
                # Check for suspicious ports
                if self.threat_intel.is_suspicious_port(conn.remote_port):
                    suspicious.append(SuspiciousActivity(
                        activity_type="suspicious_port_connection",
                        severity="medium",
                        description=f"Connection to suspicious port {conn.remote_port}",
                        source_ip=conn.local_address,
                        destination_ip=conn.remote_address,
                        port=conn.remote_port,
                        process_name=conn.process_name,
                        pid=conn.pid,
                        timestamp=conn.timestamp,
                        evidence={"port_type": "known_malware_port"}
                    ))
                
                # Check for unusual outbound connections from system processes
                system_processes = ['System', 'svchost.exe', 'lsass.exe', 'winlogon.exe']
                if (conn.process_name in system_processes and 
                    conn.remote_address not in ['127.0.0.1', '::1'] and
                    not self._is_private_ip(conn.remote_address)):
                    
                    suspicious.append(SuspiciousActivity(
                        activity_type="system_process_outbound",
                        severity="high",
                        description=f"System process {conn.process_name} making outbound connection",
                        source_ip=conn.local_address,
                        destination_ip=conn.remote_address,
                        port=conn.remote_port,
                        process_name=conn.process_name,
                        pid=conn.pid,
                        timestamp=conn.timestamp,
                        evidence={"unusual_behavior": "system_process_network_activity"}
                    ))
                
                # Check for high port usage by single process
                process_connections = [c for c in connections if c.pid == conn.pid]
                if len(process_connections) > self.thresholds['connection_count_threshold']:
                    suspicious.append(SuspiciousActivity(
                        activity_type="excessive_connections",
                        severity="medium",
                        description=f"Process {conn.process_name} has {len(process_connections)} connections",
                        source_ip=conn.local_address,
                        destination_ip=conn.remote_address,
                        port=conn.remote_port,
                        process_name=conn.process_name,
                        pid=conn.pid,
                        timestamp=conn.timestamp,
                        evidence={"connection_count": len(process_connections)}
                    ))
                
            except Exception as e:
                logger.error(f"Error analyzing connection: {e}")
        
        return suspicious
    
    def detect_traffic_anomalies(self, current_traffic: List[NetworkTraffic]) -> List[SuspiciousActivity]:
        """Detect traffic anomalies that might indicate malicious activity"""
        suspicious = []
        
        try:
            for traffic in current_traffic:
                interface = traffic.interface
                
                # Get baseline for this interface
                if interface in self.baseline_traffic:
                    baseline = self.baseline_traffic[interface]
                    
                    # Check for data exfiltration (unusual outbound traffic)
                    bytes_sent_diff = traffic.bytes_sent - baseline.get('bytes_sent', 0)
                    if bytes_sent_diff > self.thresholds['data_exfiltration_threshold']:
                        suspicious.append(SuspiciousActivity(
                            activity_type="data_exfiltration",
                            severity="high",
                            description=f"Unusual outbound traffic on {interface}: {bytes_sent_diff / 1024 / 1024:.1f}MB",
                            source_ip="local",
                            destination_ip="external",
                            port=0,
                            process_name="unknown",
                            pid=0,
                            timestamp=traffic.timestamp,
                            evidence={"bytes_sent": bytes_sent_diff, "interface": interface}
                        ))
                    
                    # Check for high error rates
                    error_rate = (traffic.errors_in + traffic.errors_out) / max(1, traffic.packets_sent + traffic.packets_recv)
                    if error_rate > 0.05:  # 5% error rate
                        suspicious.append(SuspiciousActivity(
                            activity_type="high_error_rate",
                            severity="medium",
                            description=f"High network error rate on {interface}: {error_rate * 100:.1f}%",
                            source_ip="local",
                            destination_ip="unknown",
                            port=0,
                            process_name="unknown",
                            pid=0,
                            timestamp=traffic.timestamp,
                            evidence={"error_rate": error_rate, "interface": interface}
                        ))
                
                # Update baseline
                self.baseline_traffic[interface] = {
                    'bytes_sent': traffic.bytes_sent,
                    'bytes_recv': traffic.bytes_recv,
                    'packets_sent': traffic.packets_sent,
                    'packets_recv': traffic.packets_recv
                }
                
        except Exception as e:
            logger.error(f"Error detecting traffic anomalies: {e}")
        
        return suspicious
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False
    
    def get_network_summary(self) -> Dict:
        """Get network activity summary"""
        with self.data_lock:
            connections = self.connections.copy()
            suspicious = self.suspicious_activities.copy()
        
        # Count connections by type
        connection_types = {}
        processes = {}
        ports = {}
        
        for conn in connections:
            # Count by status
            status = conn.status
            connection_types[status] = connection_types.get(status, 0) + 1
            
            # Count by process
            process = conn.process_name
            processes[process] = processes.get(process, 0) + 1
            
            # Count by port
            port = conn.remote_port
            ports[port] = ports.get(port, 0) + 1
        
        # Recent suspicious activities
        recent_suspicious = [s for s in suspicious if 
                           (datetime.now() - s.timestamp).total_seconds() < 3600]  # Last hour
        
        return {
            'total_connections': len(connections),
            'connection_types': connection_types,
            'top_processes': dict(sorted(processes.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            'suspicious_activities': len(recent_suspicious),
            'suspicious_by_severity': {
                'high': len([s for s in recent_suspicious if s.severity == 'high']),
                'medium': len([s for s in recent_suspicious if s.severity == 'medium']),
                'low': len([s for s in recent_suspicious if s.severity == 'low'])
            }
        }
    
    def get_recent_suspicious_activities(self, hours: int = 24) -> List[SuspiciousActivity]:
        """Get suspicious activities from recent hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.data_lock:
            return [activity for activity in self.suspicious_activities 
                   if activity.timestamp >= cutoff_time]
    
    def _trigger_alerts(self, suspicious_activities: List[SuspiciousActivity]):
        """Trigger alerts for suspicious activities"""
        for activity in suspicious_activities:
            for callback in self.alert_callbacks:
                try:
                    callback(activity)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
    
    def _monitor_loop(self):
        """Main network monitoring loop"""
        logger.info("Starting network monitoring loop")
        
        while self.running:
            try:
                # Get current network state
                connections = self.get_network_connections()
                traffic = self.get_network_traffic()
                
                # Detect suspicious activities
                suspicious_connections = self.detect_suspicious_connections(connections)
                suspicious_traffic = self.detect_traffic_anomalies(traffic)
                
                all_suspicious = suspicious_connections + suspicious_traffic
                
                # Store data
                with self.data_lock:
                    self.connections = connections
                    self.traffic_history.extend(traffic)
                    self.suspicious_activities.extend(all_suspicious)
                    
                    # Maintain history size
                    if len(self.traffic_history) > self.history_size:
                        self.traffic_history = self.traffic_history[-self.history_size:]
                    
                    if len(self.suspicious_activities) > self.history_size:
                        self.suspicious_activities = self.suspicious_activities[-self.history_size:]
                
                # Trigger alerts
                if all_suspicious:
                    self._trigger_alerts(all_suspicious)
                    logger.warning(f"Detected {len(all_suspicious)} suspicious network activities")
                
                time.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in network monitoring loop: {e}")
                time.sleep(5)
        
        logger.info("Network monitoring loop stopped")
    
    def start(self):
        """Start network monitoring"""
        if self.running:
            logger.warning("Network monitor is already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Network monitor started")
    
    def stop(self):
        """Stop network monitoring"""
        if not self.running:
            logger.warning("Network monitor is not running")
            return
        
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("Network monitor stopped")
    
    def export_data(self, filename: str, hours: int = 24):
        """Export network monitoring data to JSON file"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            with self.data_lock:
                # Filter recent data
                recent_connections = [c for c in self.connections if c.timestamp >= cutoff_time]
                recent_traffic = [t for t in self.traffic_history if t.timestamp >= cutoff_time]
                recent_suspicious = [s for s in self.suspicious_activities if s.timestamp >= cutoff_time]
            
            export_data = {
                'export_time': datetime.now().isoformat(),
                'duration_hours': hours,
                'summary': self.get_network_summary(),
                'connections': [
                    {
                        **asdict(conn),
                        'timestamp': conn.timestamp.isoformat()
                    }
                    for conn in recent_connections
                ],
                'traffic': [
                    {
                        **asdict(traffic),
                        'timestamp': traffic.timestamp.isoformat()
                    }
                    for traffic in recent_traffic
                ],
                'suspicious_activities': [
                    {
                        **asdict(activity),
                        'timestamp': activity.timestamp.isoformat()
                    }
                    for activity in recent_suspicious
                ]
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Exported network data to {filename}")
            
        except Exception as e:
            logger.error(f"Error exporting network data: {e}")
            raise


if __name__ == "__main__":
    # Example usage
    def on_suspicious_activity(activity):
        print(f"SUSPICIOUS ACTIVITY [{activity.severity.upper()}]: {activity.description}")
        print(f"  Process: {activity.process_name} (PID: {activity.pid})")
        print(f"  Network: {activity.source_ip} -> {activity.destination_ip}:{activity.port}")
        print(f"  Time: {activity.timestamp}")
        print()
    
    monitor = NetworkMonitor(update_interval=5.0)
    monitor.add_alert_callback(on_suspicious_activity)
    
    try:
        monitor.start()
        print("Network monitor started. Press Ctrl+C to stop...")
        
        while True:
            time.sleep(10)
            summary = monitor.get_network_summary()
            print(f"Connections: {summary['total_connections']}, "
                  f"Suspicious: {summary['suspicious_activities']}")
            
    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        monitor.stop()
        print("Network monitor stopped.")
