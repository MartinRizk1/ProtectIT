#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
RESET='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BLUE}║       ${PURPLE}ProtectIT Malware Scanner Startup${BLUE}      ║${RESET}"
echo -e "${BLUE}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# Make sure the script runs from the project directory
cd "$(dirname "$0")"

# Check Python installation
echo -e "🔍 ${YELLOW}Checking Python installation...${RESET}"
if command -v python3 &> /dev/null; then
    PYTHON_VER=$(python3 --version)
    echo -e "✅ ${GREEN}${PYTHON_VER} found${RESET}"
else
    echo -e "❌ ${RED}Python 3 not found. Please install Python 3.8 or later:${RESET}"
    echo -e "   ${YELLOW}MacOS:${RESET} brew install python"
    echo -e "   ${YELLOW}Linux:${RESET} sudo apt install python3 python3-venv"
    echo -e "   ${YELLOW}Windows:${RESET} Download from https://www.python.org/downloads/"
    exit 1
fi

# Check Node.js installation
echo -e "🔍 ${YELLOW}Checking Node.js installation...${RESET}"
if command -v node &> /dev/null; then
    NODE_VER=$(node --version)
    echo -e "✅ ${GREEN}Node.js ${NODE_VER} found${RESET}"
else
    echo -e "❌ ${RED}Node.js not found. Please install Node.js 16 or later:${RESET}"
    echo -e "   ${YELLOW}MacOS:${RESET} brew install node"
    echo -e "   ${YELLOW}Linux:${RESET} sudo apt install nodejs npm"
    echo -e "   ${YELLOW}Windows:${RESET} Download from https://nodejs.org/"
    exit 1
fi

# Check for MongoDB
echo -e "📊 ${YELLOW}Checking if MongoDB is running...${RESET}"
MONGO_RUNNING=false
if command -v mongod &> /dev/null; then
    if pgrep mongod > /dev/null; then
        echo -e "✅ ${GREEN}MongoDB is running${RESET}"
        MONGO_RUNNING=true
    else
        echo -e "⚠️  ${YELLOW}MongoDB is not running. Attempting to start...${RESET}"
        if command -v brew &> /dev/null; then
            brew services start mongodb-community
            if [ $? -eq 0 ]; then
                echo -e "✅ ${GREEN}MongoDB started successfully${RESET}"
                MONGO_RUNNING=true
            fi
        elif [ -f /etc/init.d/mongodb ]; then
            sudo service mongodb start
            if [ $? -eq 0 ]; then
                echo -e "✅ ${GREEN}MongoDB started successfully${RESET}"
                MONGO_RUNNING=true
            fi
        else
            echo -e "❌ ${RED}Failed to start MongoDB. Please start it manually.${RESET}"
            echo -e "   ${YELLOW}MacOS:${RESET} brew services start mongodb-community"
            echo -e "   ${YELLOW}Linux:${RESET} sudo service mongodb start"
            echo -e "   ${YELLOW}Windows:${RESET} Start MongoDB service from Services"
        fi
    fi
else
    echo -e "❌ ${RED}MongoDB not found. Please install MongoDB:${RESET}"
    echo -e "   ${YELLOW}MacOS:${RESET} brew tap mongodb/brew && brew install mongodb-community"
    echo -e "   ${YELLOW}Linux:${RESET} sudo apt install -y mongodb"
    echo -e "   ${YELLOW}Windows:${RESET} Download from https://www.mongodb.com/try/download/community"
fi

# Check permissions
echo -e "🛡️ ${YELLOW}Checking script permissions...${RESET}"
chmod +x start_scanner_service.sh start_backend.sh start_frontend.sh
echo -e "✅ ${GREEN}Script permissions set${RESET}"

# Function to start a service
start_service() {
    local name=$1
    local script=$2
    local port=$3

    echo ""
    echo -e "🚀 ${YELLOW}Starting ${name} on port ${port}...${RESET}"
    
    # Check if the port is already in use
    if lsof -i :$port > /dev/null; then
        echo -e "⚠️  ${RED}Port $port is already in use. ${name} may already be running.${RESET}"
        echo -e "   You can check with: lsof -i :$port"
        echo -e "   To kill the process: kill \$(lsof -t -i :$port)"
    else
        # Make script executable
        chmod +x $script
        
        # Start in a new terminal window
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            echo -e "${BLUE}Opening new terminal window...${RESET}"
            osascript -e "tell application \"Terminal\" to do script \"cd $(pwd) && ./$script\""
        else
            # Linux (including WSL)
            if command -v gnome-terminal &> /dev/null; then
                gnome-terminal -- bash -c "cd $(pwd) && ./$script; read -p 'Press enter to close...'"
            elif command -v xterm &> /dev/null; then
                xterm -e "cd $(pwd) && ./$script; read -p 'Press enter to close...'" &
            else
                # Fallback to running in background
                echo -e "${YELLOW}Could not open a new terminal window. Starting in background...${RESET}"
                (./$script > $name.log 2>&1 &)
                echo -e "${BLUE}Logs available in ${name}.log${RESET}"
            fi
        fi
        
        echo -e "✅ ${GREEN}${name} starting...${RESET}"
        sleep 2  # Give some time to start
    fi
}

# Start Scanner Service
start_service "Scanner Service" "start_scanner_service.sh" "5001"

# Start Backend
start_service "Backend" "start_backend.sh" "5000"

# Start Frontend
start_service "Frontend" "start_frontend.sh" "3000"

echo ""
echo -e "${GREEN}==================================${RESET}"
echo -e "${GREEN}  All services are starting up!   ${RESET}"
echo -e "${GREEN}==================================${RESET}"
echo ""
echo -e "🌐 ${BLUE}Access the application at:${RESET} ${PURPLE}http://localhost:3000${RESET}"
echo ""
echo -e "⚠️  ${YELLOW}Note: Services may take a few moments to fully initialize${RESET}"
