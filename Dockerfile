# Use Python 3.9 slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - \
    && apt-get install -y nodejs

# Copy backend requirements and install
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend code
COPY backend/ /app/backend/

# Copy frontend package.json and install dependencies
COPY frontend/package*.json /app/frontend/
WORKDIR /app/frontend
RUN npm install

# Copy frontend code
COPY frontend/ /app/frontend/

# Build frontend
RUN npm run build

# Switch back to app directory
WORKDIR /app

# Copy startup scripts
COPY start_backend.sh start_frontend.sh ./
RUN chmod +x *.sh

# Expose ports
EXPOSE 3000 5000

# Create startup script for container
RUN echo '#!/bin/bash\n\
cd /app/backend && python app.py &\n\
cd /app/frontend && npm start &\n\
wait' > /app/start_container.sh && chmod +x /app/start_container.sh

# Start the application
CMD ["/app/start_container.sh"]
