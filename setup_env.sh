#!/bin/bash

# Check if .env file exists, if not, copy the template
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.template .env
    echo "Please update the .env file with your specific configurations."
    echo ""
fi

# Check if .env file exists in node-backend directory
if [ ! -f ./node-backend/.env ]; then
    echo "Creating node-backend/.env file..."
    if [ ! -d ./node-backend ]; then
        mkdir -p ./node-backend
    fi
    cat > ./node-backend/.env << EOF
PORT=5000
MONGODB_URI=mongodb://localhost:27017/protectit
PYTHON_SCANNER_URL=http://localhost:5001
UPLOAD_DIR=../uploads
EOF
    echo "Created node-backend/.env with default values."
    echo ""
fi

# Check if .env file exists in frontend directory
if [ ! -f ./frontend/.env ]; then
    echo "Creating frontend/.env file..."
    if [ ! -d ./frontend ]; then
        mkdir -p ./frontend
    fi
    cat > ./frontend/.env << EOF
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_WS_URL=ws://localhost:5000
EOF
    echo "Created frontend/.env with default values."
    echo ""
fi

echo "Environment files have been set up. Please review them and update with appropriate values."
echo "WARNING: Never commit .env files to version control!"
