import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';
import { rateLimit } from 'express-rate-limit';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import userRoutes from './routes/userRoutes.js';
import imageRoutes from './routes/imageRoutes.js';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Verify essential environment variables
const requiredEnvVars = [
  'RAZORPAY_KEY_ID',
  'RAZORPAY_KEY_SECRET',
  'MONGODB_URI',
  'JWT_SECRET'
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars);
  process.exit(1);
}

// Enhanced CORS configuration
const corsOptions = {
  origin: [
    'https://tech-rraj-client-repo-xwx8.vercel.app',
    'http://localhost:3000',
    ...(NODE_ENV === 'development' ? ['http://localhost:5000'] : [])
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'token']
};

// Trust proxy for proper IP handling
app.set('trust proxy', 1);

// ======================
// SECURITY MIDDLEWARE
// ======================
app.use(helmet());
app.use(mongoSanitize());
app.use(cookieParser());

// Rate limiting - simplified version that works with Render
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip, // Simplified IP handling for Render
  skip: (req) => req.path.startsWith('/api/health')
});
app.use(limiter);

// ======================
// APPLICATION MIDDLEWARE
// ======================
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Enhanced Request Logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, {
    ip: req.ip,
    xForwardedFor: req.headers['x-forwarded-for'],
    userAgent: req.headers['user-agent']
  });
  next();
});

// ======================
// ROUTES
// ======================
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'AI Image Generator API',
    documentation: {
      userRoutes: '/api/user',
      imageRoutes: '/api/image',
      healthCheck: '/api/health'
    },
    environment: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// API Routes
app.use('/api/user', userRoutes);
app.use('/api/image', imageRoutes);

// Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
    environment: NODE_ENV
  });
});

// ======================
// ERROR HANDLING
// ======================
// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Endpoint ${req.method} ${req.path} not found`,
    code: "ENDPOINT_NOT_FOUND"
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.stack}`);

  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(statusCode).json({
    success: false,
    message,
    code: err.code || "SERVER_ERROR",
    ...(NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ======================
// DATABASE & SERVER START
// ======================
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: "ImageGen",
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB connected successfully');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  }
};

const startServer = async () => {
  try {
    await connectDB();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`
      ==================================
       🚀 Server running in ${NODE_ENV} mode
       🔗 http://localhost:${PORT}
       ⏰ ${new Date().toLocaleString()}
       ✅ Allowed Origins: ${corsOptions.origin.join(', ')}
      ==================================
      `);
    });

    // Graceful shutdown
    const shutdown = async () => {
      console.log('\n🛑 Shutting down gracefully...');
      server.close(async () => {
        await mongoose.connection.close();
        console.log('✅ All connections closed');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
};

startServer();