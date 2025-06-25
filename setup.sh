#!/bin/bash

# Text formatting
BOLD=$(tput bold)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

# Print colored header
print_header() {
  echo "${BOLD}${BLUE}===============================================${RESET}"
  echo "${BOLD}${BLUE}  ProtectIT - Advanced Malware Scanner Setup   ${RESET}"
  echo "${BOLD}${BLUE}===============================================${RESET}"
  echo
}

# Print section
print_section() {
  echo
  echo "${BOLD}${GREEN}▶ $1${RESET}"
  echo "${BOLD}${GREEN}----------------------------------------${RESET}"
}

# Print error
print_error() {
  echo "${BOLD}${RED}ERROR: $1${RESET}"
}

# Print success
print_success() {
  echo "${BOLD}${GREEN}✓ $1${RESET}"
}

# Print warning
print_warning() {
  echo "${BOLD}${YELLOW}⚠ $1${RESET}"
}

# Check if command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Main setup function
setup_protectit() {
  print_header

  # Check for Python
  print_section "Checking for Python 3.8+"
  if command_exists python3; then
    python_version=$(python3 --version | cut -d' ' -f2)
    print_success "Python $python_version found"
  else
    print_error "Python 3 not found"
    echo "Please install Python 3.8 or later:"
    echo "  - macOS: brew install python"
    echo "  - Ubuntu: sudo apt install python3 python3-venv"
    echo "  - Windows: Download from https://www.python.org/downloads/"
    exit 1
  fi

  # Check for Node.js
  print_section "Checking for Node.js 16+"
  if command_exists node; then
    node_version=$(node --version)
    print_success "Node.js $node_version found"
  else
    print_error "Node.js not found"
    echo "Please install Node.js 16 or later:"
    echo "  - macOS: brew install node"
    echo "  - Ubuntu: sudo apt install nodejs npm"
    echo "  - Windows: Download from https://nodejs.org/"
    exit 1
  fi

  # Check for MongoDB
  print_section "Checking for MongoDB"
  if command_exists mongod; then
    mongo_running=false
    if pgrep mongod > /dev/null; then
      print_success "MongoDB is running"
      mongo_running=true
    else
      print_warning "MongoDB is installed but not running"
      echo "Attempting to start MongoDB..."
      
      if command_exists brew; then
        brew services start mongodb-community
        if [ $? -eq 0 ]; then
          print_success "MongoDB started successfully"
          mongo_running=true
        else
          print_error "Failed to start MongoDB with Homebrew"
        fi
      elif [ -f /etc/init.d/mongodb ]; then
        sudo service mongodb start
        if [ $? -eq 0 ]; then
          print_success "MongoDB started successfully"
          mongo_running=true
        else
          print_error "Failed to start MongoDB service"
        fi
      else
        print_error "Could not automatically start MongoDB"
        echo "Please start MongoDB manually:"
        echo "  - macOS: brew services start mongodb-community"
        echo "  - Ubuntu: sudo service mongodb start or sudo systemctl start mongodb"
        echo "  - Windows: Start MongoDB service from Services"
      fi
    fi
    
    if [ "$mongo_running" = false ]; then
      print_warning "MongoDB is not running. Setup will continue, but you'll need to start MongoDB before running the application."
    fi
  else
    print_warning "MongoDB not found"
    echo "Installing MongoDB is recommended for full functionality:"
    echo "  - macOS: brew tap mongodb/brew && brew install mongodb-community"
    echo "  - Ubuntu: sudo apt install -y mongodb"
    echo "  - Windows: Download from https://www.mongodb.com/try/download/community"
    
    print_warning "Setup will continue, but you'll need to install MongoDB before running the application with database support."
  fi

  # Check for Docker
  print_section "Checking for Docker installation"
  
  if command_exists docker && command_exists docker-compose; then
    print_success "Docker and Docker Compose found."
    
    echo "Do you want to set up ProtectIT using Docker? (y/n)"
    read -r use_docker
    
    if [[ $use_docker =~ ^[Yy]$ ]]; then
      setup_docker
      return
    else
      print_warning "Proceeding with manual setup..."
    fi
  else
    print_warning "Docker not found. Proceeding with manual setup..."
  fi
  
  setup_manual
}
source venv/bin/activate
python app.py
EOF

# Frontend startup script
cat > start_frontend.sh << 'EOF'
#!/bin/bash
echo "🌐 Starting ProtectIT Frontend..."
cd frontend
npm start
EOF

# Make scripts executable
chmod +x start_backend.sh
chmod +x start_frontend.sh

echo "🎉 ProtectIT setup complete!"
echo ""
echo "To start the application:"
echo "1. Run backend: ./start_backend.sh"
echo "2. Run frontend: ./start_frontend.sh"
echo "3. Open http://localhost:3000 in your browser"
echo ""
echo "⚠️  Note: Run these commands in separate terminal windows"
