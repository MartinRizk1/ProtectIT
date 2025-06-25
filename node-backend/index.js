import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import axios from 'axios';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import http from 'http';

import FileModel from './models/File.js';
import ScanResultModel from './models/ScanResult.js';
import SystemInfoModel from './models/SystemInfo.js';

// Load environment variables
dotenv.config();

const app = express();
const server = http.createServer(app);

// Setup WebSocket server for real-time updates
const wss = new WebSocketServer({ server });
wss.on('connection', (ws) => {
  console.log('WebSocket client connected');
  
  // Send initial connection message
  ws.send(JSON.stringify({
    type: 'connection',
    message: 'Connected to ProtectIT Scanner'
  }));
  
  ws.on('close', () => {
    console.log('WebSocket client disconnected');
  });
});

// Broadcast to all WebSocket clients
const broadcast = (data) => {
  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(JSON.stringify(data));
    }
  });
};

app.use(cors());
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Create uploads directory if it doesn't exist
const uploadDir = process.env.UPLOAD_DIR || 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  },
});
const upload = multer({ 
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// File upload endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    
    console.log(`File uploaded: ${file.originalname}`);
    
    const fileDoc = await FileModel.create({
      filename: file.filename,
      originalname: file.originalname,
      path: file.path,
      size: file.size,
      mimetype: file.mimetype,
      uploadDate: new Date(),
    });
    
    res.json({ file: fileDoc });
  } catch (err) {
    console.error('Error uploading file:', err);
    res.status(500).json({ error: err.message });
  }
});

// Scan single file endpoint
app.post('/api/scan/file', async (req, res) => {
  try {
    const { fileId } = req.body;
    
    if (!fileId) return res.status(400).json({ error: 'File ID is required' });
    
    const fileDoc = await FileModel.findById(fileId);
    if (!fileDoc) return res.status(404).json({ error: 'File not found' });
    
    const scanId = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Send scan started message to WebSocket clients
    broadcast({
      type: 'scan_started',
      scanId,
      file: fileDoc.originalname
    });
    
    // Call Python scanner service in the background
    initiateFileScan(fileDoc, scanId);
    
    res.json({
      scanId,
      status: 'started',
      file: fileDoc.originalname
    });
  } catch (err) {
    console.error('Error scanning file:', err);
    res.status(500).json({ error: err.message });
  }
});

// Scan directory endpoint
app.post('/api/scan/directory', async (req, res) => {
  try {
    const { path: dirPath } = req.body;
    
    if (!dirPath) return res.status(400).json({ error: 'Directory path is required' });
    if (!fs.existsSync(dirPath)) return res.status(404).json({ error: 'Directory not found' });
    
    const scanId = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Send scan started message to WebSocket clients
    broadcast({
      type: 'scan_started',
      scanId,
      directory: dirPath
    });
    
    // Call Python scanner service in the background
    initiateDirectoryScan(dirPath, scanId);
    
    res.json({
      scanId,
      status: 'started',
      directory: dirPath
    });
  } catch (err) {
    console.error('Error scanning directory:', err);
    res.status(500).json({ error: err.message });
  }
});

// Scan running processes endpoint
app.post('/api/scan/processes', async (req, res) => {
  try {
    const scanId = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Send scan started message to WebSocket clients
    broadcast({
      type: 'scan_started',
      scanId,
      target: 'system_processes'
    });
    
    // Call Python scanner service in the background
    initiateProcessScan(scanId);
    
    res.json({
      scanId,
      status: 'started',
      target: 'system_processes'
    });
  } catch (err) {
    console.error('Error scanning processes:', err);
    res.status(500).json({ error: err.message });
  }
});

// Full system scan endpoint
app.post('/api/scan/system', async (req, res) => {
  try {
    const scanId = new Date().toISOString().replace(/[:.]/g, '-');
    
    // Send scan started message to WebSocket clients
    broadcast({
      type: 'scan_started',
      scanId,
      target: 'full_system'
    });
    
    // Call Python scanner service in the background
    initiateSystemScan(scanId);
    
    res.json({
      scanId,
      status: 'started',
      target: 'full_system'
    });
  } catch (err) {
    console.error('Error starting system scan:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get scan result by ID
app.get('/api/results/:id', async (req, res) => {
  try {
    const scanResult = await ScanResultModel.findById(req.params.id).populate('files');
    if (!scanResult) return res.status(404).json({ error: 'Result not found' });
    res.json({ scanResult });
  } catch (err) {
    console.error('Error fetching result:', err);
    res.status(500).json({ error: err.message });
  }
});

// List all scan results with pagination
app.get('/api/results', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const results = await ScanResultModel.find()
      .sort({ scannedAt: -1 })
      .skip(skip)
      .limit(limit);
      
    const total = await ScanResultModel.countDocuments();
    
    res.json({
      results,
      pagination: {
        total,
        page,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Error listing results:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get system information
app.get('/api/system-info', async (req, res) => {
  try {
    // Call Python scanner service to get system info
    const response = await axios.get(`${process.env.PYTHON_SCANNER_URL}/system-info`);
    
    // Store system info in MongoDB
    await SystemInfoModel.create({
      cpuUsage: response.data.cpu_usage,
      memoryUsage: response.data.memory_usage,
      diskUsage: response.data.disk_usage,
      activeProcesses: response.data.active_processes,
      timestamp: new Date()
    });
    
    res.json(response.data);
  } catch (err) {
    console.error('Error getting system info:', err);
    res.status(500).json({ error: err.message });
  }
});

// Scanner service integration functions

async function initiateFileScan(fileDoc, scanId) {
  try {
    const formData = new FormData();
    formData.append('file', fs.createReadStream(fileDoc.path));
    formData.append('scan_id', scanId);
    
    const response = await axios.post(`${process.env.PYTHON_SCANNER_URL}/scan/file`, formData, {
      headers: {
        ...formData.getHeaders(),
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
    });
    
    // Store scan result
    const scanResult = await ScanResultModel.create({
      scanId,
      files: [fileDoc._id],
      result: response.data,
      target: 'file',
      targetDetails: fileDoc.originalname,
      scannedAt: new Date(),
    });
    
    // Broadcast result to WebSocket clients
    broadcast({
      type: 'scan_complete',
      scanId,
      result: response.data,
      resultId: scanResult._id
    });
    
    return scanResult;
  } catch (error) {
    console.error('Error in file scan:', error);
    
    // Broadcast error to WebSocket clients
    broadcast({
      type: 'scan_error',
      scanId,
      error: error.message
    });
    
    throw error;
  }
}

async function initiateDirectoryScan(dirPath, scanId) {
  try {
    const response = await axios.post(`${process.env.PYTHON_SCANNER_URL}/scan/directory`, {
      path: dirPath,
      scan_id: scanId
    });
    
    // Create placeholder for scan result - it will be updated by webhook
    await ScanResultModel.create({
      scanId,
      target: 'directory',
      targetDetails: dirPath,
      result: { status: 'in_progress' },
      scannedAt: new Date(),
    });
    
    return response.data;
  } catch (error) {
    console.error('Error in directory scan:', error);
    
    // Broadcast error to WebSocket clients
    broadcast({
      type: 'scan_error',
      scanId,
      error: error.message
    });
    
    throw error;
  }
}

async function initiateProcessScan(scanId) {
  try {
    const response = await axios.post(`${process.env.PYTHON_SCANNER_URL}/scan/processes`, {
      scan_id: scanId
    });
    
    // Store scan result
    const scanResult = await ScanResultModel.create({
      scanId,
      target: 'processes',
      result: response.data,
      scannedAt: new Date(),
    });
    
    // Broadcast result to WebSocket clients
    broadcast({
      type: 'scan_complete',
      scanId,
      result: response.data,
      resultId: scanResult._id
    });
    
    return scanResult;
  } catch (error) {
    console.error('Error in process scan:', error);
    
    // Broadcast error to WebSocket clients
    broadcast({
      type: 'scan_error',
      scanId,
      error: error.message
    });
    
    throw error;
  }
}

async function initiateSystemScan(scanId) {
  try {
    const response = await axios.post(`${process.env.PYTHON_SCANNER_URL}/scan/system`, {
      scan_id: scanId
    });
    
    // Create placeholder for scan result - it will be updated by webhook
    await ScanResultModel.create({
      scanId,
      target: 'system',
      result: { status: 'in_progress' },
      scannedAt: new Date(),
    });
    
    return response.data;
  } catch (error) {
    console.error('Error in system scan:', error);
    
    // Broadcast error to WebSocket clients
    broadcast({
      type: 'scan_error',
      scanId,
      error: error.message
    });
    
    throw error;
  }
}

// Webhook for Python scanner to send progress updates
app.post('/api/webhook/scan-progress', async (req, res) => {
  try {
    const { scanId, progress, currentItem } = req.body;
    
    // Broadcast progress to WebSocket clients
    broadcast({
      type: 'scan_progress',
      scanId,
      progress,
      currentItem
    });
    
    res.status(200).send('Progress update received');
  } catch (err) {
    console.error('Error processing progress webhook:', err);
    res.status(500).json({ error: err.message });
  }
});

// Webhook for Python scanner to send scan results
app.post('/api/webhook/scan-result', async (req, res) => {
  try {
    const { scanId, result } = req.body;
    
    // Update scan result in database
    const scanResult = await ScanResultModel.findOneAndUpdate(
      { scanId },
      { result },
      { new: true }
    );
    
    if (!scanResult) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Broadcast result to WebSocket clients
    broadcast({
      type: 'scan_complete',
      scanId,
      result,
      resultId: scanResult._id
    });
    
    res.status(200).send('Result received');
  } catch (err) {
    console.error('Error processing result webhook:', err);
    res.status(500).json({ error: err.message });
  }
});

// Serve static files (for production - built frontend)
app.use(express.static(path.join(__dirname, '../frontend/dist')));

// All other GET requests not handled before will return the React app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`ProtectIT API Server running on port ${PORT}`);
});
