import multer from 'multer';

// Use memory storage to process the buffer (encrypt) before writing to IPFS
const storage = multer.memoryStorage();

// Set file size limit to 10MB
export const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } 
});
