import express from 'express';
import { 
  registerUser, 
  loginUser, 
  getUserProfile,
  updateUserProfile,
  changePassword,
  createOrder,
  verifyPayment,
  getTransactions
} from '../controllers/userController.js';
import authUser from '../middlewares/auth.js';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many requests from this IP, please try again later'
});

// Async handler with error catching
const asyncHandler = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Route Error:`, error);
    next(error);
  }
};

// Public routes
router.post('/register', authLimiter, asyncHandler(registerUser));
router.post('/login', authLimiter, asyncHandler(loginUser));
router.post('/verify-payment', asyncHandler(verifyPayment));

// Protected routes (require authentication)
router.use(authUser);

router.get('/profile', asyncHandler(getUserProfile));
router.put('/profile', asyncHandler(updateUserProfile));
router.put('/change-password', asyncHandler(changePassword));
router.post('/create-order', asyncHandler(createOrder));
router.get('/transactions', asyncHandler(getTransactions));

// CORS Preflight Options
router.options('*', (req, res) => {
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.status(204).end();
});

export default router;