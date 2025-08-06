# ProtectIT Configuration File

# Database Configuration
DATABASE_URL = "sqlite:///protectit.db"
THREAT_DB_URL = "sqlite:///threats.db"

# Security Settings
MAX_SCAN_DEPTH = 10  # Maximum directory depth to scan
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size for scanning
SCAN_TIMEOUT = 300  # 5 minutes timeout for individual file scans

# API Configuration
API_HOST = "0.0.0.0"
API_PORT = 5000
DEBUG_MODE = True

# Real-time Protection Settings
REAL_TIME_PROTECTION = False  # Enable/disable real-time file monitoring
QUARANTINE_ENABLED = True  # Enable/disable quarantine functionality
AUTO_QUARANTINE = False  # Automatically quarantine detected threats

# Scanning Options
SCAN_ARCHIVES = True  # Scan inside ZIP, RAR files
SCAN_COMPRESSED = True  # Scan compressed files
HEURISTIC_SCANNING = True  # Enable heuristic analysis
SIGNATURE_SCANNING = True  # Enable signature-based detection

# Performance Settings
MAX_CONCURRENT_SCANS = 4  # Maximum number of concurrent file scans
SCAN_CHUNK_SIZE = 1024 * 1024  # Read files in 1MB chunks
PROGRESS_UPDATE_INTERVAL = 100  # Update progress every N files

# Logging Configuration
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE = "logs/protectit.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# Network Settings
ENABLE_VIRUS_TOTAL = False  # Enable VirusTotal API integration
VIRUS_TOTAL_API_KEY = ""  # Your VirusTotal API key
REQUEST_TIMEOUT = 30  # Network request timeout in seconds

# Update Settings
AUTO_UPDATE_SIGNATURES = True  # Automatically update threat signatures
UPDATE_INTERVAL = 24  # Hours between signature updates
UPDATE_URL = "https://api.protectit.com/signatures"

# Exclusions
EXCLUDED_EXTENSIONS = [
    ".txt", ".log", ".cfg", ".ini", ".xml", ".json",
    ".md", ".rst", ".pdf", ".doc", ".docx"
]

EXCLUDED_DIRECTORIES = [
    "/System/Library/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "node_modules/",
    ".git/",
    "__pycache__/",
    ".venv/",
    "venv/"
]

# Alert Settings
EMAIL_ALERTS = False  # Send email alerts for threats
SMTP_SERVER = ""
SMTP_PORT = 587
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
ALERT_EMAIL = ""

# Quarantine Settings
QUARANTINE_DIRECTORY = "quarantine/"
QUARANTINE_ENCRYPTION = True  # Encrypt quarantined files
QUARANTINE_MAX_SIZE = 1024 * 1024 * 1024  # 1GB max quarantine size
