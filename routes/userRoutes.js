import express from 'express';
import { 
  registerUser, 
  loginUser, 
  getUserProfile,
  createOrder,
  verifyPayment,
  getTransactions,
  updateUserProfile,
  changePassword
} from '../controllers/userController.js';
import authUser from '../middlewares/auth.js';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Improved async handler with error logging
const asyncHandler = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Route Error:`, error);
    next(error); // Pass to central error handler
  }
};

// Public routes
router.post('/register', authLimiter, asyncHandler(registerUser));
router.post('/login', authLimiter, asyncHandler(loginUser));
router.post('/verify-payment', asyncHandler(verifyPayment));

// Protected routes
router.use(authUser); // Apply auth middleware to all routes below

router.get('/profile', asyncHandler(getUserProfile));
router.put('/profile', asyncHandler(updateUserProfile));
router.put('/change-password', asyncHandler(changePassword));
router.post('/create-order', asyncHandler(createOrder));
router.get('/transactions', asyncHandler(getTransactions));

// CORS Preflight Options
const handleOptions = (req, res) => {
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.status(204).end();
};

// Setup OPTIONS handlers for all routes
router.options('/register', handleOptions);
router.options('/login', handleOptions);
router.options('/profile', handleOptions);
router.options('/create-order', handleOptions);
router.options('/transactions', handleOptions);

export default router;