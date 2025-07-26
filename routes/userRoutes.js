import express from 'express';
import { 
  registerUser, 
  loginUser, 
  userCredits, 
  paymentRazorpay, 
  verifyRazorpay 
} from '../controllers/userController.js';
import authUser from '../middlewares/auth.js';

const router = express.Router();

// Improved async handler
const asyncHandler = (fn) => (req, res, next) => 
  Promise.resolve(fn(req, res, next)).catch(next);

// Public routes
router.post('/register', asyncHandler(registerUser));
router.post('/login', asyncHandler(loginUser));
router.post('/verify-razor', asyncHandler(verifyRazorpay));

// Protected routes
router.get('/credits', authUser, asyncHandler(userCredits));
router.post('/pay-razor', authUser, asyncHandler(paymentRazorpay));

// Add this to explicitly handle OPTIONS for /login
router.options('/login', (req, res) => {
  res.header('Access-Control-Allow-Methods', 'POST');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.status(200).end();
});

export default router;