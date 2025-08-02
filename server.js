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

// Load environment variables with validation
dotenv.config();

// Initialize Express app with enhanced settings
const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Validate critical environment variables
const requiredEnvVars = {
  RAZORPAY_KEY_ID: 'Razorpay Key ID',
  RAZORPAY_KEY_SECRET: 'Razorpay Key Secret',
  MONGODB_URI: 'MongoDB Connection URI',
  JWT_SECRET: 'JWT Secret Key'
};

const missingVars = Object.entries(requiredEnvVars)
  .filter(([key]) => !process.env[key])
  .map(([_, name]) => name);

if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  process.exit(1);
}

// Enhanced development logging
if (NODE_ENV === 'development') {
  mongoose.set('debug', (collectionName, method, query, doc) => {
    console.log(`MongoDB: ${collectionName}.${method}`, {
      query,
      doc
    });
  });

  app.use((req, res, next) => {
    console.log('Incoming Request:', {
      method: req.method,
      path: req.path,
      headers: req.headers,
      body: req.body
    });
    next();
  });
}

// Robust CORS configuration

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'https://tech-rraj-client-repo-xwx8.vercel.app',
      'http://localhost:3000',
      ...(NODE_ENV === 'development' ? ['http://localhost:5000'] : [])
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('CORS Blocked for origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'token'],
  maxAge: 86400
};

// Add explicit OPTIONS handler
app.options('*', cors(corsOptions));

// Trust proxy with proper IP handling
app.set('trust proxy', 1);

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
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(mongoSanitize({
  replaceWith: '_'
}));

app.use(cookieParser(process.env.COOKIE_SECRET || 'default-secret', {
  httpOnly: true,
  secure: NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 86400000
}));

// Fixed Rate Limiting with proper IPv6 handling
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => {
    try {
      // Properly handle IPv6 addresses
      const forwarded = req.headers['x-forwarded-for'];
      const ip = forwarded 
        ? forwarded.split(/\s*,\s*/)[0] 
        : req.socket.remoteAddress;
      
      // Normalize IPv6 addresses
     
      return ip || 'unknown-ip';
    } catch (err) {
      console.error('Rate limit key generation failed:', err);
      return 'fallback-ip';
    }
  },
  skip: (req) => req.path.startsWith('/api/health'),
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message,
      code: "RATE_LIMIT_EXCEEDED",
      retryAfter: options.windowMs / 1000
    });
  }
});

app.use(limiter);

// ======================
// APPLICATION MIDDLEWARE
// ======================
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

app.use(express.json({
  limit: '10kb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf.toString());
    } catch (e) {
      throw new Error('Invalid JSON payload');
    }
  }
}));

app.use(express.urlencoded({
  extended: true,
  limit: '10kb',
  parameterLimit: 50
}));

// Enhanced Request Logging with error tracking
app.use((req, res, next) => {
  const requestStart = Date.now();

  res.on('finish', () => {
    const { statusCode } = res;
    const processingTime = Date.now() - requestStart;

    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, {
      status: statusCode,
      processingTime: `${processingTime}ms`,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      ...(statusCode >= 400 && {
        error: res.locals.error || 'Unknown error'
      })
    });
  });

  next();
});

// ======================
// ROUTES
// ======================
// API Documentation
app.get('/', (req, res) => {
  try {
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
  } catch (err) {
    console.error('Root route handler error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error'
    });
  }
});

// API Routes with error wrapping
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

app.use('/api/user', userRoutes);
app.use('/api/image', imageRoutes);

// Enhanced Health Check
app.get('/api/health', asyncHandler(async (req, res) => {
  const healthStatus = {
    status: 'healthy',
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    load: process.cpuUsage()
  };

  // Additional MongoDB health check
  try {
    await mongoose.connection.db.admin().ping();
  } catch (err) {
    healthStatus.status = 'degraded';
    healthStatus.database = 'unresponsive';
    healthStatus.error = err.message;
  }

  res.status(healthStatus.status === 'healthy' ? 200 : 503).json(healthStatus);
}));

// ======================
// ERROR HANDLING
// ======================
// 404 Handler
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: `Endpoint ${req.method} ${req.path} not found`,
    code: "ENDPOINT_NOT_FOUND",
    suggestions: [
      '/api/user for user operations',
      '/api/image for image operations'
    ]
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  // Store error for request logging
  res.locals.error = err.message;

  console.error(`[${new Date().toISOString()}] ERROR: ${err.stack}`);

  // Handle different error types
  let statusCode = err.statusCode || 500;
  let message = 'Internal Server Error';
  let code = "SERVER_ERROR";
  let details = null;

  if (err instanceof RateLimitError) {
    statusCode = 429;
    message = "Too many requests, please try again later";
    code = "RATE_LIMIT_EXCEEDED";
  } 
  else if (err.name === 'ValidationError') {
    statusCode = 400;
    message = "Validation Error";
    code = "VALIDATION_ERROR";
    details = Object.values(err.errors).map(e => e.message);
  }
  else if (err.name === 'MongoServerError') {
    if (err.code === 11000) {
      statusCode = 409;
      message = "Duplicate key error";
      code = "CONFLICT";
      details = `Duplicate value for field: ${Object.keys(err.keyPattern)[0]}`;
    } else {
      message = "Database operation failed";
      code = "DATABASE_ERROR";
    }
  }
  else if (err.isAxiosError) {
    statusCode = 502;
    message = "Payment gateway communication failed";
    code = "RAZORPAY_COMMUNICATION_ERROR";
    details = err.response?.data;
  }
  else if (err.message === 'Invalid JSON payload') {
    statusCode = 400;
    message = "Invalid request body";
    code = "BAD_REQUEST";
  }
  else if (err.message) {
    message = err.message;
  }

  // Prepare error response
  const errorResponse = {
    success: false,
    message,
    code,
    ...(NODE_ENV !== 'production' && { 
      stack: err.stack,
      details
    })
  };

  // Special handling for 500 errors
  if (statusCode === 500) {
    console.error('Critical Server Error:', err);
    // Consider notifying monitoring system here
  }

  res.status(statusCode).json(errorResponse);
});

// ======================
// DATABASE & SERVER START
// ======================
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      dbName: "ImageGen",
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 45000,
      retryWrites: true,
      retryReads: true,
      connectTimeoutMS: 30000
    });

    console.log('✅ MongoDB connected successfully to:', conn.connection.host);

    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
      // Consider implementing reconnection logic here
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('MongoDB reconnected');
    });

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
       ✅ Allowed Origins: ${[
         'https://tech-rraj-client-repo-xwx8.vercel.app',
         'http://localhost:3000',
         ...(NODE_ENV === 'development' ? ['http://localhost:5000'] : [])
       ].join(', ')}
      ==================================
      `);
    });

    // Enhanced graceful shutdown
    const shutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);
      try {
        await new Promise((resolve) => {
          server.close((err) => {
            if (err) {
              console.error('Server close error:', err);
              process.exit(1);
            }
            resolve();
          });
        });

        await mongoose.connection.close();
        console.log('✅ All connections closed');
        process.exit(0);
      } catch (err) {
        console.error('Graceful shutdown failed:', err);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    
    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      // Consider implementing proper error reporting here
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

// Start the server with error handling
startServer().catch(err => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});