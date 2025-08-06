#!/usr/bin/env python3
"""
ProtectIT System Monitor
Real-time system resource monitoring and performance tracking
"""

import os
import time
import threading
import logging
import psutil
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import queue

logger = logging.getLogger(__name__)


@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: datetime
    cpu_usage: float
    cpu_count: int
    memory_usage: float
    memory_total: int
    memory_available: int
    disk_usage: float
    disk_total: int
    disk_free: int
    network_sent: int
    network_recv: int
    network_connections: int
    process_count: int
    load_average: List[float]
    boot_time: datetime
    uptime: float


@dataclass
class ProcessInfo:
    """Information about a running process"""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    cpu_percent: float
    memory_percent: float
    memory_info: Dict
    create_time: datetime
    status: str
    username: str
    connections: List[Dict]


class SystemMonitor:
    """Advanced system monitoring with real-time metrics collection"""
    
    def __init__(self, update_interval: float = 1.0, history_size: int = 1000):
        self.update_interval = update_interval
        self.history_size = history_size
        self.running = False
        self.monitor_thread = None
        self.metrics_history: List[SystemMetrics] = []
        self.metrics_lock = threading.Lock()
        self.callbacks: List[Callable[[SystemMetrics], None]] = []
        
        # Performance thresholds
        self.thresholds = {
            'cpu_critical': 90.0,
            'cpu_warning': 75.0,
            'memory_critical': 90.0,
            'memory_warning': 80.0,
            'disk_critical': 95.0,
            'disk_warning': 85.0
        }
        
        # Alert tracking
        self.active_alerts = set()
        self.alert_callbacks: List[Callable[[str, str, Dict], None]] = []
        
        logger.info("SystemMonitor initialized")
    
    def add_metrics_callback(self, callback: Callable[[SystemMetrics], None]):
        """Add callback function to be called with new metrics"""
        self.callbacks.append(callback)
    
    def add_alert_callback(self, callback: Callable[[str, str, Dict], None]):
        """Add callback function to be called when alerts are triggered"""
        self.alert_callbacks.append(callback)
    
    def get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        try:
            # CPU metrics
            cpu_usage = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            network_connections = len(psutil.net_connections())
            
            # Process count
            process_count = len(psutil.pids())
            
            # Load average (Unix/Linux only)
            try:
                load_avg = list(os.getloadavg())
            except (OSError, AttributeError):
                load_avg = [0.0, 0.0, 0.0]
            
            # Boot time and uptime
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = time.time() - psutil.boot_time()
            
            metrics = SystemMetrics(
                timestamp=datetime.now(),
                cpu_usage=cpu_usage,
                cpu_count=cpu_count,
                memory_usage=memory.percent,
                memory_total=memory.total,
                memory_available=memory.available,
                disk_usage=disk.percent,
                disk_total=disk.total,
                disk_free=disk.free,
                network_sent=network.bytes_sent,
                network_recv=network.bytes_recv,
                network_connections=network_connections,
                process_count=process_count,
                load_average=load_avg,
                boot_time=boot_time,
                uptime=uptime
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            raise
    
    def get_process_list(self, sort_by: str = 'cpu_percent', limit: int = 20) -> List[ProcessInfo]:
        """Get list of running processes sorted by specified metric"""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 
                                           'cpu_percent', 'memory_percent', 
                                           'memory_info', 'create_time', 
                                           'status', 'username']):
                try:
                    proc_info = proc.info
                    
                    # Get network connections for this process
                    try:
                        connections = [
                            {
                                'family': conn.family.name,
                                'type': conn.type.name,
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status
                            }
                            for conn in proc.connections()
                        ]
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        connections = []
                    
                    process_info = ProcessInfo(
                        pid=proc_info['pid'],
                        name=proc_info['name'] or 'Unknown',
                        exe=proc_info['exe'] or 'Unknown',
                        cmdline=proc_info['cmdline'] or [],
                        cpu_percent=proc_info['cpu_percent'] or 0.0,
                        memory_percent=proc_info['memory_percent'] or 0.0,
                        memory_info=proc_info['memory_info']._asdict() if proc_info['memory_info'] else {},
                        create_time=datetime.fromtimestamp(proc_info['create_time']) if proc_info['create_time'] else datetime.now(),
                        status=proc_info['status'] or 'unknown',
                        username=proc_info['username'] or 'unknown',
                        connections=connections
                    )
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Sort processes by specified metric
            if sort_by in ['cpu_percent', 'memory_percent']:
                processes.sort(key=lambda p: getattr(p, sort_by), reverse=True)
            elif sort_by == 'memory_info':
                processes.sort(key=lambda p: p.memory_info.get('rss', 0), reverse=True)
            elif sort_by == 'create_time':
                processes.sort(key=lambda p: p.create_time, reverse=True)
            
            return processes[:limit]
            
        except Exception as e:
            logger.error(f"Error getting process list: {e}")
            return []
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Identify potentially suspicious processes"""
        suspicious = []
        
        try:
            processes = self.get_process_list(sort_by='cpu_percent', limit=100)
            
            for proc in processes:
                suspicion_score = 0
                reasons = []
                
                # High CPU usage
                if proc.cpu_percent > 80:
                    suspicion_score += 3
                    reasons.append('High CPU usage')
                
                # High memory usage
                if proc.memory_percent > 50:
                    suspicion_score += 2
                    reasons.append('High memory usage')
                
                # Suspicious executable names
                suspicious_names = ['crypto', 'miner', 'bot', 'trojan', 'virus', 
                                  'malware', 'rootkit', 'keylog', 'backdoor']
                if any(name in proc.name.lower() for name in suspicious_names):
                    suspicion_score += 5
                    reasons.append('Suspicious process name')
                
                # Suspicious locations
                suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', 'AppData\\Temp']
                if any(path in proc.exe for path in suspicious_paths):
                    suspicion_score += 3
                    reasons.append('Suspicious executable location')
                
                # Many network connections
                if len(proc.connections) > 10:
                    suspicion_score += 2
                    reasons.append('Many network connections')
                
                # Running as different user than expected
                if proc.username in ['nobody', 'www-data'] and proc.cpu_percent > 10:
                    suspicion_score += 2
                    reasons.append('Unusual user context')
                
                if suspicion_score >= 3:
                    proc.suspicion_score = suspicion_score
                    proc.suspicion_reasons = reasons
                    suspicious.append(proc)
            
            return sorted(suspicious, key=lambda p: p.suspicion_score, reverse=True)
            
        except Exception as e:
            logger.error(f"Error identifying suspicious processes: {e}")
            return []
    
    def check_alerts(self, metrics: SystemMetrics):
        """Check for system alerts based on thresholds"""
        alerts = []
        
        # CPU alerts
        if metrics.cpu_usage >= self.thresholds['cpu_critical']:
            alert_id = 'cpu_critical'
            if alert_id not in self.active_alerts:
                alerts.append(('critical', 'CPU usage critically high', {
                    'current': metrics.cpu_usage,
                    'threshold': self.thresholds['cpu_critical']
                }))
                self.active_alerts.add(alert_id)
        elif metrics.cpu_usage >= self.thresholds['cpu_warning']:
            alert_id = 'cpu_warning'
            if alert_id not in self.active_alerts:
                alerts.append(('warning', 'CPU usage high', {
                    'current': metrics.cpu_usage,
                    'threshold': self.thresholds['cpu_warning']
                }))
                self.active_alerts.add(alert_id)
        else:
            self.active_alerts.discard('cpu_critical')
            self.active_alerts.discard('cpu_warning')
        
        # Memory alerts
        if metrics.memory_usage >= self.thresholds['memory_critical']:
            alert_id = 'memory_critical'
            if alert_id not in self.active_alerts:
                alerts.append(('critical', 'Memory usage critically high', {
                    'current': metrics.memory_usage,
                    'threshold': self.thresholds['memory_critical']
                }))
                self.active_alerts.add(alert_id)
        elif metrics.memory_usage >= self.thresholds['memory_warning']:
            alert_id = 'memory_warning'
            if alert_id not in self.active_alerts:
                alerts.append(('warning', 'Memory usage high', {
                    'current': metrics.memory_usage,
                    'threshold': self.thresholds['memory_warning']
                }))
                self.active_alerts.add(alert_id)
        else:
            self.active_alerts.discard('memory_critical')
            self.active_alerts.discard('memory_warning')
        
        # Disk alerts
        if metrics.disk_usage >= self.thresholds['disk_critical']:
            alert_id = 'disk_critical'
            if alert_id not in self.active_alerts:
                alerts.append(('critical', 'Disk usage critically high', {
                    'current': metrics.disk_usage,
                    'threshold': self.thresholds['disk_critical']
                }))
                self.active_alerts.add(alert_id)
        elif metrics.disk_usage >= self.thresholds['disk_warning']:
            alert_id = 'disk_warning'
            if alert_id not in self.active_alerts:
                alerts.append(('warning', 'Disk usage high', {
                    'current': metrics.disk_usage,
                    'threshold': self.thresholds['disk_warning']
                }))
                self.active_alerts.add(alert_id)
        else:
            self.active_alerts.discard('disk_critical')
            self.active_alerts.discard('disk_warning')
        
        # Trigger alert callbacks
        for level, message, data in alerts:
            for callback in self.alert_callbacks:
                try:
                    callback(level, message, data)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
    
    def get_metrics_history(self, duration_minutes: int = 60) -> List[SystemMetrics]:
        """Get metrics history for specified duration"""
        with self.metrics_lock:
            cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
            return [m for m in self.metrics_history if m.timestamp >= cutoff_time]
    
    def get_metrics_summary(self, duration_minutes: int = 60) -> Dict:
        """Get summary statistics for metrics over specified duration"""
        history = self.get_metrics_history(duration_minutes)
        
        if not history:
            return {}
        
        cpu_values = [m.cpu_usage for m in history]
        memory_values = [m.memory_usage for m in history]
        disk_values = [m.disk_usage for m in history]
        
        return {
            'duration_minutes': duration_minutes,
            'sample_count': len(history),
            'cpu': {
                'avg': sum(cpu_values) / len(cpu_values),
                'min': min(cpu_values),
                'max': max(cpu_values),
                'current': cpu_values[-1] if cpu_values else 0
            },
            'memory': {
                'avg': sum(memory_values) / len(memory_values),
                'min': min(memory_values),
                'max': max(memory_values),
                'current': memory_values[-1] if memory_values else 0
            },
            'disk': {
                'avg': sum(disk_values) / len(disk_values),
                'min': min(disk_values),
                'max': max(disk_values),
                'current': disk_values[-1] if disk_values else 0
            }
        }
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        logger.info("Starting system monitoring loop")
        
        while self.running:
            try:
                # Collect metrics
                metrics = self.get_current_metrics()
                
                # Store in history
                with self.metrics_lock:
                    self.metrics_history.append(metrics)
                    
                    # Maintain history size limit
                    if len(self.metrics_history) > self.history_size:
                        self.metrics_history = self.metrics_history[-self.history_size:]
                
                # Check for alerts
                self.check_alerts(metrics)
                
                # Call callbacks
                for callback in self.callbacks:
                    try:
                        callback(metrics)
                    except Exception as e:
                        logger.error(f"Error in metrics callback: {e}")
                
                time.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Wait longer on error
        
        logger.info("System monitoring loop stopped")
    
    def start(self):
        """Start system monitoring"""
        if self.running:
            logger.warning("System monitor is already running")
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("System monitor started")
    
    def stop(self):
        """Stop system monitoring"""
        if not self.running:
            logger.warning("System monitor is not running")
            return
        
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("System monitor stopped")
    
    def export_metrics(self, filename: str, duration_minutes: int = 60):
        """Export metrics history to JSON file"""
        try:
            history = self.get_metrics_history(duration_minutes)
            
            # Convert to serializable format
            export_data = {
                'export_time': datetime.now().isoformat(),
                'duration_minutes': duration_minutes,
                'metrics_count': len(history),
                'metrics': [
                    {
                        **asdict(metrics),
                        'timestamp': metrics.timestamp.isoformat(),
                        'boot_time': metrics.boot_time.isoformat()
                    }
                    for metrics in history
                ]
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Exported {len(history)} metrics to {filename}")
            
        except Exception as e:
            logger.error(f"Error exporting metrics: {e}")
            raise


if __name__ == "__main__":
    # Example usage
    def on_metrics(metrics):
        print(f"CPU: {metrics.cpu_usage:.1f}%, Memory: {metrics.memory_usage:.1f}%, "
              f"Disk: {metrics.disk_usage:.1f}%")
    
    def on_alert(level, message, data):
        print(f"ALERT [{level.upper()}]: {message} - {data}")
    
    monitor = SystemMonitor(update_interval=2.0)
    monitor.add_metrics_callback(on_metrics)
    monitor.add_alert_callback(on_alert)
    
    try:
        monitor.start()
        print("System monitor started. Press Ctrl+C to stop...")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping system monitor...")
        monitor.stop()
        print("System monitor stopped.")
