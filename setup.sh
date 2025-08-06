#!/bin/bash

# ProtectIT Setup Script
# This script automates the setup and configuration of ProtectIT

echo "====================================="
echo "ProtectIT - Installation and Setup"
echo "====================================="

# Check for required tools
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required but not installed. Aborting."; exit 1; }
command -v pip3 >/dev/null 2>&1 || { echo "Pip for Python 3 is required but not installed. Aborting."; exit 1; }

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Project root: $PROJECT_ROOT"

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p "$PROJECT_ROOT/uploads"
mkdir -p "$PROJECT_ROOT/quarantine"
mkdir -p "$PROJECT_ROOT/scanner_service/models"
mkdir -p "$PROJECT_ROOT/scanner_service/temp"

# Setup Scanner Service
echo "Setting up Scanner Service..."
cd "$PROJECT_ROOT" || exit

# Create Python virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
if [[ "$OSTYPE" == "darwin"* || "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Activating virtual environment (Unix/Mac)..."
    source venv/bin/activate
elif [[ "$OSTYPE" == "cygwin" || "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "Activating virtual environment (Windows)..."
    source venv/Scripts/activate
else
    echo "Unsupported OS. Please manually activate the virtual environment."
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r scanner_service/requirements.txt

# Make sure PyTorch is properly installed
echo "Verifying PyTorch installation..."
python -c "import torch; print(f'PyTorch version: {torch.__version__}; CUDA available: {torch.cuda.is_available()}')" || echo "Warning: PyTorch not installed correctly"

# Setup Node.js Backend
echo "Setting up Node.js Backend..."
cd "$PROJECT_ROOT/node-backend" || exit

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

# Create .env file if not exists
if [ ! -f .env ]; then
    echo "Creating .env file for Node.js backend..."
    cat > .env << EOL
PORT=5000
MONGODB_URI=mongodb://localhost:27017/protectit
PYTHON_SCANNER_URL=http://localhost:5001
UPLOAD_DIR=../uploads
EOL
    echo ".env file created"
else
    echo ".env file already exists, skipping"
fi

# Setup Frontend
echo "Setting up Frontend..."
cd "$PROJECT_ROOT/frontend" || exit

# Install Frontend dependencies
echo "Installing Frontend dependencies..."
npm install

# Create .env file for frontend if not exists
if [ ! -f .env ]; then
    echo "Creating .env file for frontend..."
    cat > .env << EOL
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_WS_URL=ws://localhost:5000
EOL
    echo "Frontend .env file created"
else
    echo "Frontend .env file already exists, skipping"
fi

# Create sample test malware signatures
echo "Creating sample YARA rules..."
cd "$PROJECT_ROOT/scanner-service/rules" || exit

# Add additional rules if basic_rules.yar already exists but doesn't have our advanced rules
if [ -f basic_rules.yar ]; then
    echo "YARA rules file already exists, checking for updates..."
    if ! grep -q "malicious_pe_characteristics" basic_rules.yar; then
        echo "Adding advanced rules to existing YARA file..."
        cat >> basic_rules.yar << 'EOL'

rule malicious_pe_characteristics {
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        $antivm1 = "VirtualBox" nocase
        $antivm2 = "VMware" nocase
        $antivm3 = "QEMU" nocase
        $antivm4 = "Sandbox" nocase
        $antidbg1 = "IsDebuggerPresent" nocase
        $antidbg2 = "CheckRemoteDebuggerPresent" nocase
        $antidbg3 = "NtQueryInformationProcess" nocase
        
    condition:
        ($mz at 0) and $pe and (any of ($antivm*) or any of ($antidbg*))
}

rule suspicious_network_activity {
    strings:
        $network1 = "InternetOpenUrl" nocase
        $network2 = "URLDownloadToFile" nocase
        $network3 = "WSAStartup" nocase
        $network4 = "connect(" nocase
        $network5 = "recv(" nocase
        $network6 = "send(" nocase
        $network7 = "socket(" nocase
        $c2server1 = /https?:\/\/[a-z0-9]{10,}\.com\//
        $c2server2 = /https?:\/\/[a-z0-9]{6,}\.(xyz|top|club|info|cc|io|ru)\//
        
    condition:
        3 of them
}
EOL
    fi
fi

# Return to project root
cd "$PROJECT_ROOT" || exit

echo "====================================="
echo "ProtectIT Setup Complete!"
echo "====================================="
echo ""
echo "To start the application:"
echo ""
echo "1. Start the Scanner Service:"
echo "   cd scanner-service"
echo "   source venv/bin/activate  # On Windows: venv\\Scripts\\activate"
echo "   python app.py"
echo ""
echo "2. Start the Backend Server:"
echo "   cd node-backend"
echo "   npm start"
echo ""
echo "3. Start the Frontend:"
echo "   cd frontend"
echo "   npm start"
echo ""
echo "The application will be available at: http://localhost:3000"
echo "====================================="
