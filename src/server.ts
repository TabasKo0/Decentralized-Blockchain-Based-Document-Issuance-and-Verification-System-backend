import dotenv from 'dotenv';
dotenv.config();

import app from './app';

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`Document Issuance Backend Server is running!`);
  console.log(`Listening on: http://localhost:${PORT}`);
  console.log(`Environment:  ${process.env.NODE_ENV || 'development'}`);
  console.log(`Sepolia RPC:  ${process.env.SEPOLIA_RPC_URL ? 'Configured' : 'Missing (using fallback)'}`);
  console.log(`Relayer Key:  ${process.env.SEPOLIA_PRIVATE_KEY ? 'Configured' : 'Missing (using default)'}`);
  console.log(`Contract:     ${process.env.CONTRACT_ADDRESS || 'Not configured'}`);
  console.log(`====================================================`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});
