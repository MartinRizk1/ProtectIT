#!/usr/bin/env python3
"""
ProtectIT Web Dashboard - Modern Clean UI
Real-time monitoring and control dashboard for the malware detection system
"""

import os
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import psutil

from malware_detector import ThreatDatabase, SystemMetrics, ScanResult

logger = logging.getLogger(__name__)


class DashboardServer:
    """Web dashboard server for real-time monitoring with modern UI"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
        self.host = host
        self.port = port
        self.debug = debug
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.app.config['SECRET_KEY'] = 'protectit_secret_key_2023'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.db = ThreatDatabase()
        self.running = False
        
        # Setup routes
        self._setup_routes()
        self._setup_socket_events()
        
        # Background thread for real-time updates
        self.monitor_thread = None
        
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return self._render_dashboard()
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get scanning statistics"""
            try:
                stats = self._get_scan_statistics()
                return jsonify(stats)
            except Exception as e:
                logger.error(f"Error getting stats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/recent-scans')
        def get_recent_scans():
            """Get recent scan results"""
            try:
                limit = request.args.get('limit', 50, type=int)
                scans = self.db.get_recent_scans(limit)
                return jsonify(scans)
            except Exception as e:
                logger.error(f"Error getting recent scans: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats')
        def get_threats():
            """Get detected threats"""
            try:
                threats = self.db.get_threats()
                return jsonify(threats)
            except Exception as e:
                logger.error(f"Error getting threats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/system-metrics')
        def get_system_metrics():
            """Get current system metrics"""
            try:
                metrics = self._get_current_system_metrics()
                return jsonify(metrics)
            except Exception as e:
                logger.error(f"Error getting system metrics: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/quarantine')
        def get_quarantine():
            """Get quarantined files"""
            try:
                quarantined = self.db.get_quarantined_files()
                return jsonify(quarantined)
            except Exception as e:
                logger.error(f"Error getting quarantine: {e}")
                return jsonify({'error': str(e)}), 500
    
    def _setup_socket_events(self):
        """Setup Socket.IO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            logger.info("Client connected to dashboard")
            emit('status', {'message': 'Connected to ProtectIT Dashboard'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            logger.info("Client disconnected from dashboard")
        
        @self.socketio.on('start_scan')
        def handle_start_scan(data):
            """Handle scan start request"""
            try:
                path = data.get('path', '/tmp')
                scan_type = data.get('type', 'quick')
                logger.info(f"Starting {scan_type} scan of {path}")
                
                # Emit scan started event
                emit('scan_started', {
                    'path': path,
                    'type': scan_type,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Here you would integrate with your scanning logic
                # For now, we'll just simulate a scan completion
                def simulate_scan():
                    time.sleep(2)  # Simulate scan time
                    emit('scan_result', {
                        'file_path': f"{path}/test_file.exe",
                        'threat_level': 'clean',
                        'confidence': 0.95,
                        'timestamp': datetime.now().isoformat()
                    })
                
                threading.Thread(target=simulate_scan, daemon=True).start()
                
            except Exception as e:
                logger.error(f"Error starting scan: {e}")
                emit('error', {'message': str(e)})
    
    def _render_dashboard(self):
        """Render the main dashboard HTML with modern design"""
        html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProtectIT - Enterprise Security Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        
        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #1a1a1a;
            --surface-1: #1e1e1e;
            --surface-2: #2a2a2a;
            --gold-primary: #d4af37;
            --gold-light: #f5d769;
            --gold-gradient: linear-gradient(135deg, #d4af37, #f5d769);
            --gold-glow: 0 0 20px rgba(212, 175, 55, 0.3);
            --success: #10b981;
            --success-light: #34d399;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
            --text-primary: #ffffff;
            --text-secondary: #d1d5db;
            --text-tertiary: #9ca3af;
            --text-muted: #6b7280;
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-2xl: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --transition-normal: 0.3s ease;
            --border-radius-md: 12px;
            --border-radius-lg: 16px;
            --border-radius-xl: 20px;
            --border-radius-full: 9999px;
            --spacing-sm: 0.5rem;
            --spacing-md: 1rem;
            --spacing-lg: 1.5rem;
            --spacing-xl: 2rem;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        html {
            scroll-behavior: smooth;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            font-size: 14px;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            overflow-x: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 15% 85%, rgba(212, 175, 55, 0.08) 0%, transparent 50%),
                radial-gradient(circle at 85% 15%, rgba(212, 175, 55, 0.06) 0%, transparent 50%),
                radial-gradient(circle at 50% 50%, rgba(212, 175, 55, 0.04) 0%, transparent 70%);
            z-index: -2;
            animation: backgroundPulse 8s ease-in-out infinite;
        }
        
        @keyframes backgroundPulse {
            0%, 100% { opacity: 0.8; }
            50% { opacity: 1; }
        }
        
        .header {
            background: linear-gradient(135deg, rgba(26, 26, 26, 0.95), rgba(30, 30, 30, 0.95));
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: var(--spacing-lg) var(--spacing-xl);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow-lg);
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
        }
        
        .logo-icon {
            width: 48px;
            height: 48px;
            background: var(--gold-gradient);
            border-radius: var(--border-radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: var(--bg-primary);
            box-shadow: var(--gold-glow);
            animation: logoGlow 3s ease-in-out infinite;
        }
        
        @keyframes logoGlow {
            0%, 100% { box-shadow: var(--gold-glow); }
            50% { box-shadow: 0 0 30px rgba(212, 175, 55, 0.5); }
        }
        
        .logo-text {
            display: flex;
            flex-direction: column;
        }
        
        .logo-title {
            font-size: 1.75rem;
            font-weight: 800;
            background: var(--gold-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1.2;
        }
        
        .logo-subtitle {
            font-size: 0.75rem;
            color: var(--text-tertiary);
            font-weight: 500;
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
            padding: var(--spacing-sm) var(--spacing-lg);
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: var(--border-radius-full);
            font-weight: 600;
            font-size: 0.875rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            animation: statusPulse 2s ease-in-out infinite;
        }
        
        @keyframes statusPulse {
            0%, 100% { 
                transform: scale(1); 
                opacity: 1; 
            }
            50% { 
                transform: scale(1.25); 
                opacity: 0.8; 
            }
        }
        
        .container {
            padding: var(--spacing-xl);
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: var(--spacing-xl);
        }
        
        .card {
            background: linear-gradient(135deg, rgba(30, 30, 30, 0.9), rgba(36, 36, 36, 0.9));
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: var(--border-radius-xl);
            padding: var(--spacing-xl);
            position: relative;
            overflow: hidden;
            transition: all var(--transition-normal);
            box-shadow: var(--shadow-lg);
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(212, 175, 55, 0.3), transparent);
        }
        
        .card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-2xl);
            border-color: rgba(212, 175, 55, 0.2);
        }
        
        .card-header {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
            margin-bottom: var(--spacing-xl);
        }
        
        .card-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, rgba(212, 175, 55, 0.2), rgba(212, 175, 55, 0.1));
            border: 1px solid rgba(212, 175, 55, 0.3);
            border-radius: var(--border-radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: var(--gold-primary);
        }
        
        .card-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
            margin: 0;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: var(--spacing-lg);
        }
        
        .metric-card {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: var(--border-radius-lg);
            padding: var(--spacing-lg);
            text-align: center;
            transition: all var(--transition-normal);
        }
        
        .metric-card:hover {
            background: rgba(255, 255, 255, 0.05);
            border-color: rgba(212, 175, 55, 0.2);
            transform: translateY(-2px);
        }
        
        .metric-value {
            font-size: 2rem;
            font-weight: 800;
            color: var(--gold-primary);
            line-height: 1;
            margin-bottom: var(--spacing-xs);
        }
        
        .metric-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .metric-change {
            font-size: 0.75rem;
            margin-top: var(--spacing-xs);
            padding: 2px 8px;
            border-radius: var(--border-radius-sm);
            font-weight: 600;
        }
        
        .metric-change.positive {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-light);
        }
        
        .metric-change.negative {
            background: rgba(239, 68, 68, 0.1);
            color: #f87171;
        }
        
        .progress-container {
            margin: var(--spacing-md) 0;
        }
        
        .progress-label {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: var(--spacing-sm);
            font-size: 0.875rem;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: var(--border-radius-sm);
            overflow: hidden;
            position: relative;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--gold-gradient);
            border-radius: var(--border-radius-sm);
            transition: width 0.5s ease;
            position: relative;
        }
        
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 30%, rgba(255, 255, 255, 0.2) 50%, transparent 70%);
            animation: shimmer 2s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .activity-feed {
            max-height: 350px;
            overflow-y: auto;
            padding-right: var(--spacing-sm);
        }
        
        .activity-feed::-webkit-scrollbar {
            width: 4px;
        }
        
        .activity-feed::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 2px;
        }
        
        .activity-feed::-webkit-scrollbar-thumb {
            background: var(--gold-primary);
            border-radius: 2px;
        }
        
        .activity-item {
            display: flex;
            align-items: flex-start;
            gap: var(--spacing-md);
            padding: var(--spacing-md);
            margin-bottom: var(--spacing-md);
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: var(--border-radius-md);
            transition: all var(--transition-normal);
        }
        
        .activity-item:hover {
            background: rgba(255, 255, 255, 0.04);
            border-color: rgba(212, 175, 55, 0.1);
            transform: translateX(4px);
        }
        
        .activity-icon {
            width: 32px;
            height: 32px;
            border-radius: var(--border-radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.875rem;
            flex-shrink: 0;
        }
        
        .activity-icon.info {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
        }
        
        .activity-icon.success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success-light);
        }
        
        .activity-icon.warning {
            background: rgba(245, 158, 11, 0.1);
            color: #fbbf24;
        }
        
        .activity-icon.danger {
            background: rgba(239, 68, 68, 0.1);
            color: #f87171;
        }
        
        .activity-content {
            flex: 1;
        }
        
        .activity-time {
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 500;
        }
        
        .activity-message {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 2px;
        }
        
        .chart-container {
            height: 300px;
            margin-top: var(--spacing-lg);
            position: relative;
            background: rgba(255, 255, 255, 0.02);
            border-radius: var(--border-radius-lg);
            padding: var(--spacing-md);
        }
        
        .btn-group {
            display: flex;
            gap: var(--spacing-md);
            margin-top: var(--spacing-lg);
        }
        
        .btn {
            padding: var(--spacing-md) var(--spacing-xl);
            border: none;
            border-radius: var(--border-radius-md);
            font-weight: 600;
            font-size: 0.875rem;
            cursor: pointer;
            transition: all var(--transition-normal);
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
            text-decoration: none;
            font-family: inherit;
        }
        
        .btn-primary {
            background: var(--gold-gradient);
            color: var(--bg-primary);
            box-shadow: var(--shadow-md);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg), var(--gold-glow);
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: var(--gold-primary);
            transform: translateY(-1px);
        }
        
        .input-group {
            margin-bottom: var(--spacing-lg);
        }
        
        .input-label {
            display: block;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: var(--spacing-sm);
        }
        
        .form-input {
            width: 100%;
            padding: var(--spacing-md);
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: var(--border-radius-md);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: all var(--transition-normal);
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--gold-primary);
            box-shadow: 0 0 0 3px rgba(212, 175, 55, 0.1);
        }
        
        .threat-badge {
            position: absolute;
            top: var(--spacing-lg);
            right: var(--spacing-lg);
            width: 28px;
            height: 28px;
            background: var(--danger);
            color: white;
            border-radius: 50%;
            display: none;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 700;
            animation: bounce 1s infinite;
        }
        
        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }
        
        @media (max-width: 1200px) {
            .dashboard-grid {
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: var(--spacing-md);
            }
            
            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: var(--spacing-lg);
            }
            
            .header {
                padding: var(--spacing-md);
                flex-direction: column;
                gap: var(--spacing-md);
                text-align: center;
            }
            
            .logo-title {
                font-size: 1.5rem;
            }
            
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
                gap: var(--spacing-md);
            }
            
            .btn-group {
                flex-direction: column;
            }
        }
        
        @media (max-width: 480px) {
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .metric-value {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">
                <i class="fas fa-shield-alt"></i>
            </div>
            <div class="logo-text">
                <h1 class="logo-title">ProtectIT</h1>
                <span class="logo-subtitle">Enterprise Security</span>
            </div>
        </div>
        <div class="status-indicator" id="status">
            <div class="status-dot"></div>
            <span>System Online</span>
        </div>
    </header>

    <main class="container">
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">
                        <i class="fas fa-desktop"></i>
                    </div>
                    <h3 class="card-title">System Performance</h3>
                </div>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value" id="cpu-usage">--</div>
                        <div class="metric-label">CPU Usage</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="memory-usage">--</div>
                        <div class="metric-label">Memory Usage</div>
                    </div>
                </div>
                <div class="progress-container">
                    <div class="progress-label">
                        <span>CPU Load</span>
                        <span id="cpu-percent">0%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="cpu-progress" style="width: 0%"></div>
                    </div>
                </div>
                <div class="progress-container">
                    <div class="progress-label">
                        <span>Memory Load</span>
                        <span id="memory-percent">0%</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" id="memory-progress" style="width: 0%"></div>
                    </div>
                </div>
                <div class="chart-container">
                    <canvas id="performanceChart"></canvas>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">
                        <i class="fas fa-chart-bar"></i>
                    </div>
                    <h3 class="card-title">Security Statistics</h3>
                </div>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value" id="files-processed">0</div>
                        <div class="metric-label">Files Scanned</div>
                        <div class="metric-change positive">+12% today</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="threats-detected">0</div>
                        <div class="metric-label">Threats Detected</div>
                        <div class="metric-change negative">-5% today</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="quarantined">0</div>
                        <div class="metric-label">Quarantined</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value" id="active-scans">0</div>
                        <div class="metric-label">Active Scans</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">
                        <i class="fas fa-search"></i>
                    </div>
                    <h3 class="card-title">Scan Control</h3>
                </div>
                <div class="input-group">
                    <label class="input-label" for="scan-path">Target Path</label>
                    <input type="text" id="scan-path" class="form-input" placeholder="/path/to/scan" value="/tmp">
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary" onclick="startScan()">
                        <i class="fas fa-play"></i>
                        Quick Scan
                    </button>
                    <button class="btn btn-secondary" onclick="startDeepScan()">
                        <i class="fas fa-search-plus"></i>
                        Deep Scan
                    </button>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">
                        <i class="fas fa-history"></i>
                    </div>
                    <h3 class="card-title">Recent Activity</h3>
                </div>
                <div class="activity-feed" id="activity-log">
                    <div class="activity-item">
                        <div class="activity-icon info">
                            <i class="fas fa-info"></i>
                        </div>
                        <div class="activity-content">
                            <div class="activity-time">System initialized</div>
                            <div class="activity-message">Dashboard ready for monitoring</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <div class="card-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <h3 class="card-title">Threat Monitor</h3>
                    <div class="threat-badge" id="threat-badge">!</div>
                </div>
                <div class="activity-feed" id="threat-log">
                    <div class="activity-item">
                        <div class="activity-icon success">
                            <i class="fas fa-check"></i>
                        </div>
                        <div class="activity-content">
                            <div class="activity-time">No threats detected</div>
                            <div class="activity-message">System is clean and secure</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const socket = io();
        
        const ctx = document.getElementById('performanceChart').getContext('2d');
        const performanceChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU Usage %',
                    data: [],
                    borderColor: '#d4af37',
                    backgroundColor: 'rgba(212, 175, 55, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#d4af37',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }, {
                    label: 'Memory Usage %',
                    data: [],
                    borderColor: '#60a5fa',
                    backgroundColor: 'rgba(96, 165, 250, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#60a5fa',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { 
                    legend: { 
                        labels: { 
                            color: '#ffffff',
                            font: { size: 12, family: 'Inter', weight: '500' }
                        } 
                    }
                },
                scales: {
                    x: { 
                        ticks: { 
                            color: '#9ca3af', 
                            font: { family: 'Inter', size: 11 } 
                        }, 
                        grid: { 
                            color: 'rgba(255, 255, 255, 0.08)',
                            borderColor: 'rgba(255, 255, 255, 0.1)'
                        } 
                    },
                    y: { 
                        ticks: { 
                            color: '#9ca3af', 
                            font: { family: 'Inter', size: 11 } 
                        }, 
                        grid: { 
                            color: 'rgba(255, 255, 255, 0.08)',
                            borderColor: 'rgba(255, 255, 255, 0.1)'
                        },
                        max: 100
                    }
                },
                elements: {
                    point: {
                        hoverBackgroundColor: '#d4af37'
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });
        
        socket.on('connect', function() {
            console.log('Connected to ProtectIT Dashboard');
            updateStatus('System Online', 'online');
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from ProtectIT Dashboard');
            updateStatus('System Offline', 'offline');
        });
        
        socket.on('system_metrics', function(data) {
            updateSystemMetrics(data);
        });
        
        socket.on('scan_result', function(data) {
            addActivityEntry(`Scan completed: ${data.file_path} - ${data.threat_level}`, data.threat_level);
            if (data.threat_level !== 'clean') {
                addThreatEntry(data);
                updateThreatBadge();
            }
        });
        
        socket.on('scan_started', function(data) {
            addActivityEntry(`Scan started: ${data.path} (${data.type})`, 'info');
        });
        
        function updateStatus(message, status) {
            const statusEl = document.getElementById('status');
            const statusDot = statusEl.querySelector('.status-dot');
            const statusText = statusEl.querySelector('span');
            
            statusText.textContent = message;
            
            if (status === 'online') {
                statusEl.style.background = 'rgba(16, 185, 129, 0.1)';
                statusEl.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                statusDot.style.background = '#10b981';
            } else {
                statusEl.style.background = 'rgba(239, 68, 68, 0.1)';
                statusEl.style.borderColor = 'rgba(239, 68, 68, 0.3)';
                statusDot.style.background = '#ef4444';
            }
        }
        
        function updateSystemMetrics(metrics) {
            document.getElementById('cpu-usage').textContent = metrics.cpu_usage.toFixed(1) + '%';
            document.getElementById('memory-usage').textContent = metrics.memory_usage.toFixed(1) + '%';
            
            document.getElementById('cpu-percent').textContent = metrics.cpu_usage.toFixed(1) + '%';
            document.getElementById('memory-percent').textContent = metrics.memory_usage.toFixed(1) + '%';
            document.getElementById('cpu-progress').style.width = metrics.cpu_usage + '%';
            document.getElementById('memory-progress').style.width = metrics.memory_usage + '%';
            
            const now = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
            performanceChart.data.labels.push(now);
            performanceChart.data.datasets[0].data.push(metrics.cpu_usage);
            performanceChart.data.datasets[1].data.push(metrics.memory_usage);
            
            if (performanceChart.data.labels.length > 20) {
                performanceChart.data.labels.shift();
                performanceChart.data.datasets[0].data.shift();
                performanceChart.data.datasets[1].data.shift();
            }
            
            performanceChart.update('none');
        }
        
        function addActivityEntry(message, type = 'info') {
            const log = document.getElementById('activity-log');
            const entry = document.createElement('div');
            entry.className = 'activity-item';
            
            const iconMap = {
                'malicious': 'fas fa-skull-crossbones',
                'suspicious': 'fas fa-exclamation-triangle',
                'clean': 'fas fa-check-circle',
                'info': 'fas fa-info-circle'
            };
            
            const typeClass = type === 'malicious' ? 'danger' : 
                            type === 'suspicious' ? 'warning' : 
                            type === 'clean' ? 'success' : 'info';
            
            entry.innerHTML = `
                <div class="activity-icon ${typeClass}">
                    <i class="${iconMap[type] || 'fas fa-info-circle'}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-time">${new Date().toLocaleTimeString()}</div>
                    <div class="activity-message">${message}</div>
                </div>
            `;
            
            log.insertBefore(entry, log.firstChild);
            
            while (log.children.length > 10) {
                log.removeChild(log.lastChild);
            }
        }
        
        function addThreatEntry(threat) {
            const log = document.getElementById('threat-log');
            const entry = document.createElement('div');
            entry.className = 'activity-item';
            
            const severityIcons = {
                'malicious': 'fas fa-skull-crossbones',
                'suspicious': 'fas fa-exclamation-triangle',
                'low': 'fas fa-info-circle'
            };
            
            const severityClass = threat.threat_level === 'malicious' ? 'danger' : 
                                threat.threat_level === 'suspicious' ? 'warning' : 'info';
            
            entry.innerHTML = `
                <div class="activity-icon ${severityClass}">
                    <i class="${severityIcons[threat.threat_level]}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-time">${threat.threat_level.toUpperCase()} - ${new Date().toLocaleTimeString()}</div>
                    <div class="activity-message">
                        <strong>${threat.file_path.split('/').pop()}</strong><br>
                        <small>Confidence: ${(threat.confidence * 100).toFixed(1)}% | ${threat.file_path}</small>
                    </div>
                </div>
            `;
            
            log.insertBefore(entry, log.firstChild);
            
            while (log.children.length > 10) {
                log.removeChild(log.lastChild);
            }
        }
        
        function updateThreatBadge() {
            const badge = document.getElementById('threat-badge');
            badge.style.display = 'flex';
        }
        
        function startScan() {
            const path = document.getElementById('scan-path').value || '/tmp';
            socket.emit('start_scan', { path: path, type: 'quick' });
            addActivityEntry(`Initiating quick scan of ${path}`, 'info');
        }
        
        function startDeepScan() {
            const path = document.getElementById('scan-path').value || '/tmp';
            socket.emit('start_scan', { path: path, type: 'deep' });
            addActivityEntry(`Initiating deep scan of ${path}`, 'info');
        }
        
        function loadInitialData() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('files-processed').textContent = data.total_scans || 0;
                    document.getElementById('threats-detected').textContent = (data.malicious_count || 0) + (data.suspicious_count || 0);
                    document.getElementById('quarantined').textContent = data.quarantined_count || 0;
                })
                .catch(console.error);
            
            fetch('/api/recent-scans?limit=5')
                .then(response => response.json())
                .then(data => {
                    data.forEach(scan => {
                        addActivityEntry(`${scan.file_path} - ${scan.threat_level}`, scan.threat_level);
                    });
                })
                .catch(console.error);
        }
        
        setInterval(() => {
            fetch('/api/system-metrics')
                .then(response => response.json())
                .then(data => updateSystemMetrics(data))
                .catch(console.error);
        }, 2000);
        
        loadInitialData();
        addActivityEntry('Dashboard initialized and monitoring started', 'info');
    </script>
</body>
</html>'''
        return html_content
    
    def _get_scan_statistics(self) -> Dict:
        """Get scanning statistics from database"""
        try:
            stats = self.db.get_scan_statistics()
            return stats
        except Exception as e:
            logger.error(f"Error getting scan statistics: {e}")
            return {
                'total_scans': 0,
                'malicious_count': 0,
                'suspicious_count': 0,
                'clean_count': 0,
                'quarantined_count': 0,
                'avg_scan_time': 0.0
            }
    
    def _get_current_system_metrics(self) -> Dict:
        """Get current system metrics"""
        try:
            return {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_sent': psutil.net_io_counters().bytes_sent,
                'network_recv': psutil.net_io_counters().bytes_recv,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'disk_usage': 0,
                'network_sent': 0,
                'network_recv': 0,
                'timestamp': datetime.now().isoformat()
            }
    
    def _start_monitor_thread(self):
        """Start background monitoring thread"""
        def monitor_loop():
            while self.running:
                try:
                    # Emit system metrics
                    metrics = self._get_current_system_metrics()
                    self.socketio.emit('system_metrics', metrics)
                    
                    # Check for new scan results
                    recent_scans = self.db.get_recent_scans(5)
                    for scan in recent_scans:
                        self.socketio.emit('scan_result', scan)
                    
                    time.sleep(2)  # Update every 2 seconds
                    
                except Exception as e:
                    logger.error(f"Error in monitor loop: {e}")
                    time.sleep(5)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Started monitoring thread")
    
    def start(self):
        """Start the dashboard server"""
        try:
            self.running = True
            self._start_monitor_thread()
            
            logger.info(f"Starting ProtectIT Dashboard on {self.host}:{self.port}")
            print(f"\n🚀 ProtectIT Enterprise Dashboard")
            print(f"📊 Dashboard: http://{self.host}:{self.port}")
            print(f"🖥️  Local access: http://localhost:{self.port}")
            print(f"🌐 Network access: http://{self.host}:{self.port}")
            print(f"🔒 Status: Dashboard is running and accessible on your local network")
            print(f"⚡ Features: Real-time monitoring, scanning controls, threat detection")
            
            self.socketio.run(
                self.app,
                host=self.host,
                port=self.port,
                debug=self.debug,
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            logger.error(f"Error starting dashboard: {e}")
            raise
    
    def stop(self):
        """Stop the dashboard server"""
        self.running = False
        logger.info("Dashboard server stopped")


if __name__ == "__main__":
    dashboard = DashboardServer(debug=True)
    dashboard.start()
