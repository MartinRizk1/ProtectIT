#!/bin/bash

# Make sure we're in the right directory
cd /Users/martinrizk/Desktop/Projects/ProtectIT

# Initialize git if not already initialized
git init

# Remove any previous remote and add new one
git remote remove origin 2>/dev/null
git remote add origin https://github.com/MartinRizk1/ProtectIT.git

# Configure .gitignore to ensure sensitive files are not tracked
if [ ! -f .gitignore ]; then
    echo "Creating .gitignore file"
    cat > .gitignore << 'EOF'
# Python related
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
venv/
ENV/
env/

# Node related
node_modules/
npm-debug.log
yarn-debug.log
yarn-error.log
.pnpm-debug.log
.yarn-integrity

# Environment files
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# IDE related
.idea/
.vscode/
*.swp
*.swo
*~

# Database
*.sqlite
*.sqlite3
*.db

# Logs
logs/
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Uploaded files and quarantine
uploads/*
!uploads/.gitkeep
quarantine/*
!quarantine/.gitkeep
backend/uploads/*
!backend/uploads/.gitkeep
backend/quarantine/*
!backend/quarantine/.gitkeep
scanner_service/uploads/*
!scanner_service/uploads/.gitkeep
scanner_service/temp/*
!scanner_service/temp/.gitkeep

# Misc
.DS_Store
Thumbs.db
.coverage
htmlcov/
coverage/
.pytest_cache/
EOF
fi

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: Enterprise-Grade Malware Detection System"

# Add remote repository
git remote remove origin 2>/dev/null
git remote add origin https://github.com/MartinRizk1/ProtectIT.git

# Check the default branch name
BRANCH=$(git symbolic-ref --short HEAD)

# Push to GitHub
git push -u origin $BRANCH

echo "Push completed. Check output for any errors."
