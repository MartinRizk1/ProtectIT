#!/bin/bash

# Final dependency installer for ProtectIT
# This script installs additional dependencies for the system

echo "====================================="
echo "Installing Additional ProtectIT Dependencies"
echo "====================================="

# Activate the virtual environment
source venv/bin/activate

# Install some dependencies using pip directly
echo "Installing core ML and analysis libraries..."
pip install numpy pandas scikit-learn

echo "Installing YARA alternative (yara-pattern-matcher)..."
pip install yara-pattern-matcher

echo "Installing system monitoring tools..."
pip install psutil requests python-magic

echo "====================================="
echo "ProtectIT is now ready to use!"
echo ""
echo "To run the application:"
echo "1. Activate the environment: source venv/bin/activate"
echo "2. Run the main application: python main.py"
echo "====================================="
