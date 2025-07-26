import express from 'express';
import userRoutes from './routes/userRoutes.js';
import imageRoutes from './routes/imageRoutes.js';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Enhanced CORS configuration
const corsOptions = {
  origin: [
    'https://tech-rraj-client-repo-xwx8.vercel.app',
    'http://localhost:3000',
    'http://localhost:5000' // Add your Render URL if needed
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'token']
};

// Apply CORS middleware
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight requests

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'AI Image Generator API',
    documentation: {
      userRoutes: '/api/user',
      imageRoutes: '/api/image',
      healthCheck: '/api/health'
    }
  });
});

// API Routes
app.use('/api/user', userRoutes);
app.use('/api/image', imageRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memoryUsage: process.memoryUsage()
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    requestedUrl: req.originalUrl
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

// MongoDB connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: "ImageGen",
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 45000,
    });
    console.log('Database connected successfully');
  } catch (err) {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  }
};

// Start server
const startServer = async () => {
  await connectDB();
  
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Allowed Origins: ${corsOptions.origin.join(', ')}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
      console.log('Server closed');
      mongoose.connection.close(false, () => {
        console.log('MongoDB connection closed');
        process.exit(0);
      });
    });
  });
};

startServer();