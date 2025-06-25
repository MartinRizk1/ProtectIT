#!/bin/bash

echo "🌐 Starting ProtectIT Frontend"

# Navigate to the frontend directory
cd "$(dirname "$0")/frontend"

# Install dependencies if needed
if [ ! -f ".dependencies_installed" ]; then
  echo "📦 Installing Node.js dependencies"
  npm install
  
  if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies. Please check your Node.js installation."
    exit 1
  fi
  
  touch .dependencies_installed
fi

# Check if backend is running
echo "🔄 Checking if backend is running..."
BACKEND_RUNNING=false
if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
  echo "✅ Backend is running"
  BACKEND_RUNNING=true
else
  echo "⚠️ Backend does not appear to be running. Some features may not work correctly."
  echo "   Consider starting the backend first with ./start_backend.sh"
  # Give the user a chance to abort
  read -p "Continue anyway? (y/n): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborting. Please start the backend first."
    exit 1
  fi
fi

# Start the frontend dev server
echo "🚀 Starting React frontend"
REACT_APP_BACKEND_URL=http://localhost:5000 npm start

# Note: this service should run on port 3000
