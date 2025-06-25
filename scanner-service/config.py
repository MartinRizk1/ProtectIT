import os
from pathlib import Path

# Try to load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Base paths
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
MODEL_DIR = BASE_DIR / "models"
TEMP_DIR = BASE_DIR / "temp"

# Create directories if they don't exist
UPLOAD_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)

# API Settings from environment variables or defaults
API_HOST = os.environ.get("HOST", "0.0.0.0")
API_PORT = int(os.environ.get("PORT", 5001))
DEBUG = os.environ.get("DEBUG", "True").lower() == "true"

# Backend settings from environment variables or defaults
BACKEND_URL = os.environ.get("BACKEND_WEBHOOK_URL", "http://localhost:5000/api/webhook")
WEBHOOK_SCAN_PROGRESS_URL = f"{BACKEND_URL}/scan-progress"
WEBHOOK_SCAN_RESULT_URL = f"{BACKEND_URL}/scan-result"

# Scanning Settings
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
SCAN_CHUNK_SIZE = 1024 * 1024  # 1MB
MAX_SCAN_THREADS = 4
SCAN_TIMEOUT = 300  # seconds
PROGRESS_UPDATE_INTERVAL = 1  # seconds

# Machine Learning settings
ML_MODEL_PATH = MODEL_DIR / "malware_model.joblib"
FEATURE_VECTOR_SIZE = 1000

# ClamAV Settings
USE_CLAMAV = False
CLAMD_HOST = "localhost"
CLAMD_PORT = 3310

# Suspicious file types and patterns
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.js', 
    '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.dll', '.sys',
    '.msi', '.ps1', '.reg', '.sh', '.py', '.rb'
}

SUSPICIOUS_PATTERNS = [
    b'cmd.exe /c',
    b'powershell.exe',
    b'reg add',
    b'schtasks',
    b'netsh',
    b'wscript.exe',
    b'cscript.exe',
    b'regsvr32',
    b'bitsadmin',
    b'certutil',
    b'net user ',
    b'net group ',
]

# Scoring and detection thresholds
RISK_THRESHOLD_LOW = 0.2
RISK_THRESHOLD_MEDIUM = 0.5
RISK_THRESHOLD_HIGH = 0.8
