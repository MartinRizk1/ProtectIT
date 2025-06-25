#!/bin/bash

echo "🚀 Starting ProtectIT Scanner Service"

# Navigate to the scanner service directory
cd "$(dirname "$0")/scanner-service"

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

# Check for required directories
if [ ! -d "uploads" ]; then
  echo "📁 Creating uploads directory"
  mkdir -p uploads
fi

if [ ! -d "models" ]; then
  echo "📁 Creating models directory"
  mkdir -p models
fi

# Start the scanner service
echo "🔍 Starting scanner service"
python main.py

# Note: this service should run on port 5001
