import mongoose from 'mongoose';

const SystemInfoSchema = new mongoose.Schema({
  cpuUsage: Number,
  memoryUsage: Number,
  diskUsage: Number,
  activeProcesses: Number,
  timestamp: Date,
});

export default mongoose.model('SystemInfo', SystemInfoSchema);
