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
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { RateLimitError } = require('express-rate-limit');

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
  allowedHeaders: ['Content-Type', 'Authorization', 'token', 'x-requested-with']
};

// Trust proxy for rate limiting
app.set('trust proxy', true);

// ======================
// SECURITY MIDDLEWARE
// ======================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://checkout.razorpay.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https://*.razorpay.com'],
      connectSrc: ["'self'", 'https://api.razorpay.com']
    }
  }
}));

app.use(mongoSanitize());
app.use(cookieParser());

// Enhanced Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    return forwarded ? forwarded.split(/, /)[0] : req.ip;
  },
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message,
      code: "RATE_LIMIT_EXCEEDED"
    });
  },
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
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

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
    timestamp: new Date().toISOString(),
    status: 'operational'
  });
});

// API Routes
app.use('/api/user', userRoutes);
app.use('/api/image', imageRoutes);

// Enhanced Health Check
app.get('/api/health', (req, res) => {
  const healthStatus = {
    status: 'healthy',
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    load: process.cpuUsage()
  };
  res.status(200).json(healthStatus);
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
  console.error(`[${new Date().toISOString()}] ERROR: ${err.stack}`);

  if (err instanceof RateLimitError) {
    return res.status(429).json({
      success: false,
      message: "Too many requests, please try again later",
      code: "RATE_LIMIT_EXCEEDED"
    });
  }

  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: "Validation Error",
      code: "VALIDATION_ERROR",
      errors: Object.values(err.errors).map(e => e.message)
    });
  }

  if (err.name === 'MongoServerError' && err.code === 11000) {
    return res.status(400).json({
      success: false,
      message: "Duplicate key error",
      code: "DUPLICATE_KEY",
      field: Object.keys(err.keyPattern)[0]
    });
  }

  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 ? 'Internal Server Error' : err.message;

  res.status(statusCode).json({
    success: false,
    message,
    code: err.code || "SERVER_ERROR",
    ...(NODE_ENV === 'development' && { 
      stack: err.stack,
      details: err 
    })
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
      retryWrites: true,
      retryReads: true
    });

    mongoose.connection.on('error', err => {
      console.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('MongoDB disconnected');
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

    // Enhanced graceful shutdown
    const shutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);
      try {
        await new Promise((resolve) => server.close(resolve));
        await mongoose.connection.close();
        console.log('✅ All connections closed');
        process.exit(0);
      } catch (err) {
        console.error('❌ Graceful shutdown failed:', err);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    
    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
      console.error('Uncaught Exception:', err);
      shutdown('uncaughtException');
    });
    
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
};

startServer();