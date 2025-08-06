import mongoose from 'mongoose';

const ScanResultSchema = new mongoose.Schema({
  scanId: String,
  files: [{ type: mongoose.Schema.Types.ObjectId, ref: 'File' }], // For file scans
  target: {
    type: String,
    enum: ['file', 'directory', 'processes', 'system'],
    required: true
  },
  targetDetails: String, // File name, directory path, etc.
  result: mongoose.Schema.Types.Mixed, // JSON result from Python scanner
  scannedAt: Date,
  status: {
    type: String,
    enum: ['in_progress', 'completed', 'failed'],
    default: 'in_progress'
  },
  threatCount: {
    type: Number,
    default: 0
  },
  threatCategories: {
    type: Map,
    of: Number
  }
});

// Index for faster lookups
ScanResultSchema.index({ scanId: 1 });
ScanResultSchema.index({ scannedAt: -1 });

export default mongoose.model('ScanResult', ScanResultSchema);
