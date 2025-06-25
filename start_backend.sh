#!/bin/bash

echo "🛡 Starting ProtectIT Backend"

# Navigate to the backend directory
cd "$(dirname "$0")/backend"

# Check if MongoDB is running
echo "🔍 Checking if MongoDB is running..."
if command -v mongod &> /dev/null; then
  if ! pgrep mongod > /dev/null; then
    echo "⚠️ MongoDB is not running. Attempting to start..."
    if command -v brew &> /dev/null; then
      brew services start mongodb-community
      if [ $? -ne 0 ]; then
        echo "❌ Failed to start MongoDB. Please start it manually."
        echo "   brew services start mongodb-community"
      fi
    elif [ -f /etc/init.d/mongodb ]; then
      sudo service mongodb start
      if [ $? -ne 0 ]; then
        echo "❌ Failed to start MongoDB. Please start it manually."
        echo "   sudo service mongodb start"
      fi
    else
      echo "❌ MongoDB not running. Please start it manually."
    fi
  else
    echo "✅ MongoDB is running"
  fi
else
  echo "⚠️ MongoDB command not found. Make sure MongoDB is installed and running."
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
  echo "🔄 Creating virtual environment"
  python3 -m venv venv
  if [ $? -ne 0 ]; then
    echo "❌ Failed to create virtual environment. Make sure python3-venv is installed."
    exit 1
  fi
fi

# Activate virtual environment
echo "🔄 Activating virtual environment"
source venv/bin/activate
if [ $? -ne 0 ]; then
  echo "❌ Failed to activate virtual environment."
  exit 1
fi

# Install dependencies if needed
if [ ! -f ".dependencies_installed" ]; then
  echo "📦 Installing Python dependencies"
  pip install -r requirements.txt
  if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies."
    exit 1
  fi
  touch .dependencies_installed
fi

# Create necessary directories
echo "📁 Creating uploads and quarantine directories"
mkdir -p uploads
mkdir -p quarantine

# Set environment variables for the scanner service
export SCANNER_SERVICE_URL="http://localhost:5001"
export MONGODB_URI="mongodb://localhost:27017"
export MONGODB_DB="protectit"

# Check if scanner service is running
echo "🔍 Checking if scanner service is running..."
if curl -s http://localhost:5001/health > /dev/null 2>&1; then
  echo "✅ Scanner service is running"
else
  echo "⚠️ Scanner service does not appear to be running."
  echo "   Consider starting the scanner service first with ./start_scanner_service.sh"
fi

# Run migration script if SQLite database exists
if [ -f "protectit.db" ]; then
  echo "🔄 Migrating data from SQLite to MongoDB"
  python migration/sqlite_to_mongo.py
fi

# Start the backend
echo "🔍 Starting Flask backend"
python app.py

# Note: this service should run on port 5000
