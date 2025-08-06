"""
ProtectIT - Malware Scanner Backend
Main Flask application with malware scanning capabilities
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import hashlib
import threading
import time
import json
import psutil
import requests
import subprocess
from datetime import datetime
from pathlib import Path
from pymongo import MongoClient
from bson.objectid import ObjectId

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()  # take environment variables from .env if present
    print("✅ Environment variables loaded from .env file")
except ImportError:
    print("⚠️ python-dotenv not installed, using system environment variables only")

# Helper function for retrying requests
def make_request_with_retry(method, url, max_retries=3, **kwargs):
    """Make a request with automatic retry on failure"""
    for attempt in range(max_retries + 1):
        try:
            if method.lower() == 'get':
                response = requests.get(url, **kwargs)
            elif method.lower() == 'post':
                response = requests.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error to {url}: {str(e)}"
            if attempt == max_retries:
                print(f"Final connection attempt failed: {error_msg}")
                return None
            print(f"Connection failed (attempt {attempt+1}/{max_retries+1}): {error_msg}")
            # Wait before retrying, with exponential backoff
            time.sleep(0.5 * (2 ** attempt))  # 0.5s, 1s, 2s, ...
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
            if attempt == max_retries:
                # Last attempt failed
                print(f"Final request attempt failed: {str(e)}")
                return None
            print(f"Request failed (attempt {attempt+1}/{max_retries+1}): {str(e)}")
            # Wait before retrying, with exponential backoff
            time.sleep(0.5 * (2 ** attempt))  # 0.5s, 1s, 2s, ...

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing-only')
# Configure CORS with environment variable for allowed origins
CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
CORS(app, origins=CORS_ORIGINS)
socketio = SocketIO(app, cors_allowed_origins=CORS_ORIGINS)

# Configuration
SCANNER_SERVICE_URL = os.environ.get('SCANNER_SERVICE_URL', 'http://localhost:5001')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MongoDB Configuration
MONGO_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
MONGO_DB = os.environ.get('MONGODB_DB', 'protectit')

# Initialize MongoDB client with enhanced error handling
try:
    # Attempt to connect to MongoDB with timeout
    mongo_client = MongoClient(
        MONGO_URI, 
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=5000,
        # Additional connection options for reliability
        retryWrites=True,
        w='majority',
        maxPoolSize=50
    )
    
    # Verify connection by pinging the server
    mongo_client.admin.command('ping')
    print(f"✅ Connected to MongoDB at {MONGO_URI}")
    db = mongo_client[MONGO_DB]
    
    # Database collections
    scan_results_collection = db.scan_results
    system_info_collection = db.system_info
    scans_collection = db.scans
    
except Exception as e:
    print(f"⚠️ Failed to connect to MongoDB: {e}")
    print("⚠️ The application will start, but database functionality may be limited.")
    
    # Create fallback in-memory collections for testing/development
    class InMemoryCollection:
        def __init__(self, name):
            self.name = name
            self.data = []
            self.counter = 0
            
        def insert_one(self, document):
            self.counter += 1
            doc_id = str(self.counter)
            document['_id'] = doc_id
            self.data.append(document)
            return doc_id
            
        def find(self, query=None, projection=None):
            results = [doc for doc in self.data]
            if query:
                # Simple filtering for scan_id only
                if 'scan_id' in query:
                    results = [doc for doc in results if doc.get('scan_id') == query['scan_id']]
            return MockCursor(results)
            
        def find_one(self, query, projection=None):
            for doc in self.data:
                match = True
                for k, v in query.items():
                    if k not in doc or doc[k] != v:
                        match = False
                        break
                if match:
                    return doc
            return None
            
        def update_one(self, query, update):
            doc = self.find_one(query)
            if doc and '$set' in update:
                for k, v in update['$set'].items():
                    doc[k] = v
                    
        def create_index(self, key, **kwargs):
            # Do nothing for in-memory collection
            pass
    
    class MockCursor:
        def __init__(self, data):
            self.data = data
            
        def sort(self, key, direction):
            # Simple sorting by timestamp
            if key == 'timestamp':
                self.data.sort(key=lambda x: x.get('timestamp', ''), reverse=(direction == -1))
            return self
            
        def limit(self, n):
            self.data = self.data[:n]
            return self
            
        def __iter__(self):
            return iter(self.data)
            
        def __list__(self):
            return self.data
        
    print("📝 Using in-memory database for testing purposes")
    scan_results_collection = InMemoryCollection('scan_results')
    system_info_collection = InMemoryCollection('system_info')
    scans_collection = InMemoryCollection('scans')

class MalwareScanner:
    """
    Delegator class that sends scan requests to the scanner service
    and handles communication with the database
    """
    def __init__(self):
        self.scanner_url = SCANNER_SERVICE_URL
        
    def _store_scan_start(self, scan_id, target_type, target_path):
        """Record scan start in database"""
        timestamp = datetime.now().isoformat()
        
        scan_doc = {
            'scan_id': scan_id,
            'timestamp': timestamp,
            'target_type': target_type,
            'target_path': target_path,
            'status': 'in_progress',
            'progress': 0.0
        }
        
        scans_collection.insert_one(scan_doc)
        return timestamp
    
    def _update_scan_progress(self, scan_id, progress, current_file=None):
        """Update scan progress in database"""
        update_data = {'progress': progress}
        if current_file:
            update_data['current_file'] = current_file
            
        scans_collection.update_one(
            {'scan_id': scan_id},
            {'$set': update_data}
        )
    
    def _store_scan_complete(self, scan_id, results=None):
        """Record scan completion in database"""
        timestamp = datetime.now().isoformat()
        
        # Update scan record
        scans_collection.update_one(
            {'scan_id': scan_id},
            {'$set': {
                'status': 'completed',
                'completed_at': timestamp,
                'progress': 100.0
            }}
        )
        
        # If we have detailed results, store individual threats
        if results and 'threats' in results:
            for threat in results['threats']:
                # Extract file path and hash
                file_path = threat.get('file_path', '')
                file_hash = threat.get('hash', '')
                
                # Get threat details
                threat_type = threat.get('type', 'unknown')
                threat_name = threat.get('name', 'Unknown threat')
                risk_level = threat.get('risk_level', 'MEDIUM')
                
                threat_doc = {
                    'scan_id': scan_id,
                    'timestamp': timestamp,
                    'file_path': file_path,
                    'file_hash': file_hash,
                    'threat_type': threat_type,
                    'threat_name': threat_name,
                    'risk_level': risk_level,
                    'status': 'detected'
                }
                
                scan_results_collection.insert_one(threat_doc)
    
    def _store_scan_error(self, scan_id, error_message):
        """Record scan error in database"""
        timestamp = datetime.now().isoformat()
        
        scans_collection.update_one(
            {'scan_id': scan_id},
            {'$set': {
                'status': 'failed',
                'completed_at': timestamp,
                'error': error_message
            }}
        )
    
    def scan_file(self, file_path, scan_id=None):
        """Scan a file by sending it to the scanner service"""
        # Generate scan ID if not provided
        if not scan_id:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Record scan start
        self._store_scan_start(scan_id, 'file', file_path)
        
        try:
            # Prepare the file for upload
            files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
            data = {'scan_id': scan_id}
            
            # Send to scanner service with retry logic
            response = make_request_with_retry(
                'post', 
                f"{self.scanner_url}/scan/file",
                max_retries=3,
                files=files,
                data=data,
                timeout=30
            )
            
            # Service will send updates via websocket/webhook
            return {
                'scan_id': scan_id,
                'status': 'started',
                'file': os.path.basename(file_path)
            }
        except Exception as e:
            self._store_scan_error(scan_id, str(e))
            return {
                'scan_id': scan_id,
                'status': 'error',
                'error': str(e)
            }
    
    def scan_directory(self, directory_path, scan_id=None, recursive=True):
        """Scan a directory by sending the request to the scanner service"""
        # Generate scan ID if not provided
        if not scan_id:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Record scan start
        self._store_scan_start(scan_id, 'directory', directory_path)
        
        try:
            # Prepare the request data
            data = {
                'path': directory_path,
                'recursive': recursive,
                'scan_id': scan_id
            }
            
            # Send to scanner service with retry logic
            response = make_request_with_retry(
                'post',
                f"{self.scanner_url}/scan/directory",
                max_retries=3,
                json=data,
                timeout=30
            )
            
            # Service will send updates via websocket/webhook
            return {
                'scan_id': scan_id,
                'status': 'started',
                'directory': directory_path
            }
        except Exception as e:
            self._store_scan_error(scan_id, str(e))
            return {
                'scan_id': scan_id,
                'status': 'error',
                'error': str(e)
            }
    
    def scan_processes(self, scan_id=None):
        """Scan running processes using the scanner service"""
        # Generate scan ID if not provided
        if not scan_id:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Record scan start
        self._store_scan_start(scan_id, 'processes', 'system_processes')
        
        try:
            # Prepare the request data
            data = {
                'scan_id': scan_id
            }
            
            # Send to scanner service with retry logic
            response = make_request_with_retry(
                'post',
                f"{self.scanner_url}/scan/processes",
                max_retries=3,
                json=data,
                timeout=30
            )
            
            # Service will send updates via websocket/webhook
            return {
                'scan_id': scan_id,
                'status': 'started',
                'target': 'system_processes'
            }
        except Exception as e:
            self._store_scan_error(scan_id, str(e))
            return {
                'scan_id': scan_id,
                'status': 'error',
                'error': str(e)
            }
    
    def scan_system(self, scan_id=None):
        """Perform a full system scan using the scanner service"""
        # Generate scan ID if not provided
        if not scan_id:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Record scan start
        self._store_scan_start(scan_id, 'system', 'full_system')
        
        try:
            # Prepare the request data
            data = {
                'scan_id': scan_id,
                'include_processes': True,
                'include_startup': True,
                'include_common_dirs': True
            }
            
            # Send to scanner service with retry logic
            response = make_request_with_retry(
                'post',
                f"{self.scanner_url}/scan/system",
                max_retries=3,
                json=data,
                timeout=30
            )
            
            # Service will send updates via websocket/webhook
            return {
                'scan_id': scan_id,
                'status': 'started',
                'target': 'full_system'
            }
        except Exception as e:
            self._store_scan_error(scan_id, str(e))
            return {
                'scan_id': scan_id,
                'status': 'error',
                'error': str(e)
            }
    
    def get_system_info(self):
        """Get system information from scanner service"""
        try:
            response = make_request_with_retry(
                'get',
                f"{self.scanner_url}/system-info",
                max_retries=3,
                timeout=10
            )
            
            if not response:
                raise Exception("Failed to retrieve system information")
                
            system_info = response.json()
            
            # Store system info in database
            system_info_doc = {
                'timestamp': system_info.get('timestamp', datetime.now().isoformat()),
                'cpu_usage': system_info.get('cpu_usage', 0),
                'memory_usage': system_info.get('memory_usage', 0),
                'disk_usage': system_info.get('disk_usage', 0),
                'active_processes': system_info.get('active_processes', 0)
            }
            
            try:
                system_info_collection.insert_one(system_info_doc)
            except Exception as db_err:
                print(f"Error storing system info in database: {db_err}")
            
            return system_info
        except Exception as e:
            print(f"Error getting system info: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

# Initialize scanner
scanner = MalwareScanner()

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        # Also check if scanner service is up with retry
        scanner_status = "unavailable"
        try:
            scanner_health = make_request_with_retry('get', f"{SCANNER_SERVICE_URL}/health", max_retries=1, timeout=5)
            if scanner_health and hasattr(scanner_health, 'status_code'):
                scanner_status = "healthy" if scanner_health.status_code == 200 else "unhealthy"
        except Exception as scanner_e:
            print(f"Scanner health check failed: {str(scanner_e)}")
        
        return jsonify({
            'status': 'healthy',
            'scanner_service': scanner_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'healthy',
            'scanner_service': 'unavailable',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })

@app.route('/api/system-info')
def get_system_info():
    """Get current system information"""
    try:
        system_info = scanner.get_system_info()
        return jsonify(system_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/processes', methods=['POST'])
def scan_processes():
    """Scan running processes for suspicious activity"""
    try:
        data = request.get_json() or {}
        scan_id = data.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        
        def run_scan():
            socketio.emit('scan_started', {
                'scan_id': scan_id,
                'target': 'system_processes',
                'timestamp': datetime.now().isoformat()
            })
            
            result = scanner.scan_processes(scan_id)
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': 'system_processes',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/directory', methods=['POST'])
def scan_directory():
    """Start a directory scan"""
    try:
        data = request.get_json()
        directory_path = data.get('path', '/')
        
        if not os.path.exists(directory_path):
            return jsonify({'error': 'Directory not found'}), 404
        
        # Generate scan ID
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        def run_scan():
            socketio.emit('scan_started', {
                'scan_id': scan_id,
                'directory': directory_path,
                'timestamp': datetime.now().isoformat()
            })
            
            result = scanner.scan_directory(directory_path, scan_id)
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'directory': directory_path,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a file for scanning"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save the uploaded file
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        # Return the file info
        return jsonify({
            'status': 'success',
            'filename': filename,
            'filepath': filepath,
            'size': os.path.getsize(filepath),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """Scan an uploaded file"""
    try:
        data = request.get_json() or {}
        file_path = data.get('filePath')
        
        if not file_path:
            return jsonify({'error': 'File path is required'}), 400
            
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Generate scan ID
        scan_id = data.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        file_name = os.path.basename(file_path)
        
        def run_scan():
            try:
                # Notify frontend that scan is starting
                socketio.emit('scan_started', {
                    'scan_id': scan_id,
                    'file': file_name,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Send initial progress update
                socketio.emit('scan_progress', {
                    'scan_id': scan_id,
                    'progress': 0,
                    'current_item': f'Scanning file: {file_name}',
                    'timestamp': datetime.now().isoformat()
                })
                
                # Perform the actual scan
                result = scanner.scan_file(file_path, scan_id)
                
                # If there was a scan error
                if result.get('status') == 'error':
                    socketio.emit('scan_error', {
                        'scan_id': scan_id,
                        'error': result.get('error', 'Unknown error'),
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception as e:
                # Handle any unexpected exceptions
                error_msg = str(e)
                print(f"Error during file scan: {error_msg}")
                socketio.emit('scan_error', {
                    'scan_id': scan_id,
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                })
                scanner._store_scan_error(scan_id, error_msg)
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'file': file_name,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/system', methods=['POST'])
def scan_system():
    """Start a full system scan"""
    try:
        data = request.get_json() or {}
        scan_id = data.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        
        def run_scan():
            try:
                # Notify frontend that scan is starting
                socketio.emit('scan_started', {
                    'scan_id': scan_id,
                    'target': 'full_system',
                    'timestamp': datetime.now().isoformat()
                })
                
                # Send initial progress update
                socketio.emit('scan_progress', {
                    'scan_id': scan_id,
                    'progress': 0,
                    'current_item': 'Initializing system scan...',
                    'timestamp': datetime.now().isoformat()
                })
                
                # Perform the actual scan
                result = scanner.scan_system(scan_id)
                
                # If there was a scan error (scan_system returns error status)
                if result.get('status') == 'error':
                    socketio.emit('scan_error', {
                        'scan_id': scan_id,
                        'error': result.get('error', 'Unknown error'),
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception as e:
                # Handle any unexpected exceptions
                error_msg = str(e)
                print(f"Error during system scan: {error_msg}")
                socketio.emit('scan_error', {
                    'scan_id': scan_id,
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                })
                scanner._store_scan_error(scan_id, error_msg)
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'target': 'full_system',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/results')
def get_scan_results():
    """Get scan results from database"""
    try:
        limit = request.args.get('limit', 100, type=int)
        scan_id = request.args.get('scan_id')
        
        query = {}
        if scan_id:
            query['scan_id'] = scan_id
            
        results = list(scan_results_collection.find(
            query, 
            {'_id': False}
        ).sort('timestamp', -1).limit(limit))
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/status')
def get_scan_status():
    """Get status of all scans or a specific scan"""
    try:
        scan_id = request.args.get('scan_id')
        
        if scan_id:
            # Get a specific scan
            scan = scans_collection.find_one({'scan_id': scan_id}, {'_id': False})
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
                
            return jsonify(scan)
        else:
            # Get all scans, limited
            limit = request.args.get('limit', 10, type=int)
            scans = list(scans_collection.find(
                {}, 
                {'_id': False}
            ).sort('timestamp', -1).limit(limit))
                
            return jsonify(scans)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/webhook/scan-progress', methods=['POST'])
def webhook_scan_progress():
    """Webhook endpoint for scan progress updates from scanner service"""
    try:
        data = request.get_json()
        
        if not data or 'scanId' not in data:
            error_msg = "Invalid progress data: missing 'scanId'"
            print(f"Webhook error: {error_msg}")
            return jsonify({'error': error_msg}), 400
            
        if 'progress' not in data:
            error_msg = "Invalid progress data: missing 'progress'"
            print(f"Webhook error: {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        # Update scan progress in DB
        try:
            scanner._update_scan_progress(data['scanId'], data['progress'], data.get('currentItem'))
        except Exception as db_error:
            print(f"Database error updating scan progress: {db_error}")
            # Continue to notify clients even if DB update fails
        
        # Forward to websocket clients
        try:
            socketio.emit('scan_progress', {
                'scan_id': data['scanId'],
                'progress': data['progress'],
                'current_item': data.get('currentItem', 'Scanning...'),
                'timestamp': data.get('timestamp', datetime.now().isoformat())
            })
        except Exception as socket_error:
            print(f"WebSocket error sending progress update: {socket_error}")
        
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Webhook scan progress error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/webhook/scan-result', methods=['POST'])
def webhook_scan_result():
    """Webhook endpoint for scan results from scanner service"""
    try:
        data = request.get_json()
        
        if not data or 'scanId' not in data or 'result' not in data:
            return jsonify({'error': 'Invalid result data'}), 400
        
        # Extract key information for notifications
        scan_id = data['scanId']
        result = data['result']
        threats = result.get('threats', [])
        threat_count = len(threats)
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        # Update scan record in DB
        try:
            scanner._store_scan_complete(scan_id, result)
        except Exception as db_err:
            print(f"Database error when storing scan results: {db_err}")
            # Continue with the notification even if DB fails
        
        # Prepare notification message
        notification = {
            'scan_id': scan_id,
            'result': result,
            'threat_count': threat_count,
            'timestamp': timestamp
        }
        
        # Add summary information
        if threat_count > 0:
            notification['summary'] = f"Found {threat_count} potential threats!"
            notification['severity'] = 'warning' if threat_count > 0 else 'success'
            
            # Group threats by risk level for better reporting
            threat_levels = {}
            for threat in threats:
                risk = threat.get('risk_level', 'UNKNOWN')
                if risk not in threat_levels:
                    threat_levels[risk] = 0
                threat_levels[risk] += 1
                
            notification['threat_levels'] = threat_levels
        else:
            notification['summary'] = "No threats found"
            notification['severity'] = 'success'
        
        # Forward to websocket clients
        socketio.emit('scan_complete', notification)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Error processing scan result webhook: {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    emit('connected', {'data': 'Connected to ProtectIT Scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    print("ProtectIT Backend Starting...")
    print(f"Connecting to MongoDB at {MONGO_URI}...")
    
    # Initialize MongoDB indexes
    scan_results_collection.create_index("scan_id")
    scan_results_collection.create_index("timestamp")
    scans_collection.create_index("scan_id", unique=True)
    scans_collection.create_index("timestamp")
    system_info_collection.create_index("timestamp")
    
    # Get config from environment
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"Initializing malware scanner on {host}:{port} (debug: {debug})...")
    socketio.run(app, debug=debug, host=host, port=port)
