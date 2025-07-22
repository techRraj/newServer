// routes/userRoutes.js
import express from 'express';
import { registerUser, loginUser, userCredits, paymentRazorpay, verifyRazorpay } from '../controllers/userController.js';
import authUser from '../middlewares/auth.js';

const router = express.Router();

// Utility to handle async errors
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// Public Routes
router.post('/register', asyncHandler(registerUser));
router.post('/login', asyncHandler(loginUser));

// Protected Routes
router.get('/credits', authUser, asyncHandler(userCredits));
router.post('/pay-razor', authUser, asyncHandler(paymentRazorpay));
router.post('/verify-razor', asyncHandler(verifyRazorpay));

export default router;