#!/bin/bash

# ProtectIT Setup Script - Python Only Version
# This script sets up the Python virtual environment and installs required dependencies

echo "====================================="
echo "ProtectIT - Python Environment Setup"
echo "====================================="

# Check for Python
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required but not installed. Aborting."; exit 1; }

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Project root: $PROJECT_ROOT"

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p "$PROJECT_ROOT/uploads"
mkdir -p "$PROJECT_ROOT/quarantine"
mkdir -p "$PROJECT_ROOT/scanner_service/models"
mkdir -p "$PROJECT_ROOT/scanner_service/temp"
mkdir -p "$PROJECT_ROOT/scanner_service/rules"

# Create Python virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install basic dependencies first
echo "Installing basic dependencies..."
pip install --upgrade pip wheel setuptools

# Create a minimal requirements file with core dependencies
echo "Creating minimal requirements file..."
cat > minimal_requirements.txt << EOF
Flask==2.3.3
Flask-SocketIO==5.3.6
psutil==5.9.5
requests==2.31.0
python-magic==0.4.27
yara-python==4.3.1
EOF

# Install minimal dependencies
echo "Installing minimal dependencies..."
pip install -r minimal_requirements.txt

# Create a basic YARA rule
echo "Creating basic YARA rule..."
mkdir -p "$PROJECT_ROOT/rules"
cat > "$PROJECT_ROOT/rules/basic_rules.yar" << EOF
rule SuspiciousFile {
    meta:
        description = "Detects suspicious file characteristics"
        author = "ProtectIT"
        date = "2025-08-06"
        score = 70
    strings:
        $s1 = "CreateRemoteThread" nocase
        $s2 = "VirtualAlloc" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "ShellExecute" nocase
        $s5 = "cmd.exe /c " nocase
        $s6 = "powershell.exe -e" nocase
        $s7 = "eval(base64_decode" nocase
        $s8 = "WScript.Shell" nocase
    condition:
        2 of them
}

rule MalwarePattern {
    meta:
        description = "Common malware patterns"
        author = "ProtectIT"
        date = "2025-08-06"
        score = 85
    strings:
        $a1 = "botnet" nocase
        $a2 = "backdoor" nocase
        $a3 = "trojan" nocase
        $a4 = "keylogger" nocase
        $a5 = "ransomware" nocase
    condition:
        any of them
}

rule SuspiciousPacker {
    meta:
        description = "Detects common packer signatures"
        author = "ProtectIT"
        date = "2025-08-06"
        score = 60
    strings:
        $upx = "UPX!" wide ascii
        $mpress = "MPRESS" wide ascii
        $aspack = "ASPack" wide ascii
        $fsg = "FSG!" wide ascii
        $pecompact = "PECompact" wide ascii
    condition:
        any of them
}
EOF

echo "✅ Basic setup complete!"
echo ""
echo "To run ProtectIT, activate the virtual environment and run main.py:"
echo "   source venv/bin/activate"
echo "   python main.py"
echo ""
echo "For full functionality, you may need to install additional dependencies:"
echo "   pip install numpy pandas torch scikit-learn"
echo ""
echo "====================================="
