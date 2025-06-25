import mongoose from 'mongoose';

const FileSchema = new mongoose.Schema({
  filename: String,
  originalname: String,
  path: String,
  size: Number,
  mimetype: String,
  uploadDate: Date,
});

export default mongoose.model('File', FileSchema);
