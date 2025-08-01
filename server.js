import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';
import rateLimit from 'express-rate-limit';
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

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error('❌ Razorpay keys missing in environment variables!');
  console.error('Please set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET');
  process.exit(1);
}


// Add this near the top of your server.js, after app initialization
app.set('trust proxy', 1); // Enable trust for proxy headers

// ======================
// SECURITY MIDDLEWARE
// ======================
app.use(helmet()); // Security headers
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(cookieParser()); // Parse cookies

// Rate limiting
// Replace your existing limiter with this enhanced version
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use the x-forwarded-for header if behind a proxy
    return req.headers['x-forwarded-for'] || req.ip;
  },
  skip: (req) => req.path.startsWith('/api/health')
});
app.use(limiter);

// ======================
// APPLICATION MIDDLEWARE
// ======================
app.use(cors(corsOptions)); // CORS
app.options('*', cors(corsOptions)); // Preflight requests
app.use(compression()); // Gzip compression
app.use(express.json({ limit: '10kb' })); // Body parser
app.use(express.urlencoded({ extended: true })); // URL-encoded parser

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ======================
// ROUTES
// ======================
// API Documentation
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
    message: `Endpoint ${req.method} ${req.path} not found`
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