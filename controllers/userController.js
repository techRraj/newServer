import userModel from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import validator from "validator";
import razorpay from "razorpay";
import transactionModel from "../models/transactionModel.js";
import crypto from "crypto";

// Initialize Razorpay
const razorpayInstance = new razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Password requirements
const PASSWORD_REGEX = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/;

// Utility function to remove sensitive data from user object
const sanitizeUser = (user) => {
  const userObj = user.toObject?.() || user;
  delete userObj.password;
  delete userObj.__v;
  delete userObj.verificationToken;
  delete userObj.verificationExpires;
  delete userObj.passwordResetToken;
  delete userObj.passwordResetExpires;
  return userObj;
};

// Generate random token
const generateToken = (bytes = 32) => {
  return crypto.randomBytes(bytes).toString('hex');
};

// User Controller Methods
export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "All fields are required",
        code: "MISSING_FIELDS"
      });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: "Please enter a valid email",
        code: "INVALID_EMAIL"
      });
    }

    if (!PASSWORD_REGEX.test(password)) {
      return res.status(400).json({ 
        success: false, 
        message: "Password must contain at least 8 characters, including uppercase, lowercase and numbers",
        code: "WEAK_PASSWORD"
      });
    }

    // Check if user exists
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: "Email already registered",
        code: "EMAIL_EXISTS"
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user with 5 free credits (no verification fields)
    const newUser = new userModel({ 
      name, 
      email, 
      password: hashedPassword,
      creditBalance: 5
    });

    const user = await newUser.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { 
      expiresIn: "1d" 
    });

    // Set cookie if using cookies
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    res.status(201).json({
      success: true,
      token,
      user: sanitizeUser(user),
      message: "Registration successful!"
    });

  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Registration failed",
      code: "SERVER_ERROR",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "Email and password are required",
        code: "MISSING_CREDENTIALS"
      });
    }

    // Find user with password
    const user = await userModel.findOne({ email }).select("+password");
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid credentials",
        code: "INVALID_CREDENTIALS"
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid credentials",
        code: "INVALID_CREDENTIALS"
      });
    }

    // Generate token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { 
      expiresIn: "1d" 
    });

    // Set cookie if using cookies
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });

    res.status(200).json({
      success: true,
      token,
      user: sanitizeUser(user),
      message: "Login successful"
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Login failed",
      code: "SERVER_ERROR",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const user = await userModel.findOne({ 
      verificationToken: token,
      verificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification token",
        code: "INVALID_TOKEN"
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Email verified successfully"
    });

  } catch (error) {
    console.error("Verify Email Error:", error);
    res.status(500).json({
      success: false,
      message: "Email verification failed",
      code: "SERVER_ERROR"
    });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No account found with that email",
        code: "USER_NOT_FOUND"
      });
    }

    // Generate reset token
    const resetToken = generateToken();
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password reset link would be sent to your email if email service was configured",
      resetToken // In production, don't send this back - just for demo
    });

  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Password reset failed",
      code: "SERVER_ERROR"
    });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!PASSWORD_REGEX.test(password)) {
      return res.status(400).json({ 
        success: false, 
        message: "Password must contain at least 8 characters, including uppercase, lowercase and numbers",
        code: "WEAK_PASSWORD"
      });
    }

    const user = await userModel.findOne({ 
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired password reset token",
        code: "INVALID_TOKEN"
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = Date.now();
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password reset successfully"
    });

  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Password reset failed",
      code: "SERVER_ERROR"
    });
  }
};

export const getUserProfile = async (req, res) => {
  try {
    const user = await userModel.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found",
        code: "USER_NOT_FOUND"
      });
    }

    res.status(200).json({
      success: true,
      user: sanitizeUser(user)
    });

  } catch (error) {
    console.error("Profile Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to get user profile",
      code: "SERVER_ERROR",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const updateUserProfile = async (req, res) => {
  try {
    const { name, email } = req.body;
    
    // Validate email if changed
    if (email && !validator.isEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: "Please enter a valid email",
        code: "INVALID_EMAIL"
      });
    }

    const updateData = { name };
    if (email) {
      updateData.email = email;
      updateData.isVerified = false; // Require email verification if changed
    }

    const user = await userModel.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    ).select("-password");

    res.status(200).json({
      success: true,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error("Update Profile Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Profile update failed",
      code: "SERVER_ERROR",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!PASSWORD_REGEX.test(newPassword)) {
      return res.status(400).json({ 
        success: false, 
        message: "Password must contain at least 8 characters, including uppercase, lowercase and numbers",
        code: "WEAK_PASSWORD"
      });
    }

    const user = await userModel.findById(req.user.id).select("+password");

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        message: "Current password is incorrect",
        code: "INVALID_PASSWORD"
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.passwordChangedAt = Date.now();
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully"
    });

  } catch (error) {
    console.error("Change Password Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Password change failed",
      code: "SERVER_ERROR",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const createOrder = async (req, res) => {
  try {
    const { planId } = req.body;
    const userId = req.user.id;

    if (!planId) {
      return res.status(400).json({
        success: false,
        message: "Plan ID is required",
        code: "MISSING_PLAN_ID"
      });
    }

    const plans = {
      basic: { name: "Basic", credits: 25, amount: 1000 },
      standard: { name: "Standard", credits: 70, amount: 3000 },
      premium: { name: "Premium", credits: 150, amount: 5000 }
    };

    const selectedPlan = plans[planId];
    if (!selectedPlan) {
      return res.status(400).json({
        success: false,
        message: "Invalid plan selected",
        code: "INVALID_PLAN"
      });
    }

    // Validate Razorpay keys
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
      throw new Error("Razorpay keys not configured");
    }

    const options = {
      amount: selectedPlan.amount * 100, // Convert to paise
      currency: "INR",
      receipt: `order_${Date.now()}_${userId}`,
      payment_capture: 1,
      notes: {
        userId: userId.toString(),
        planId,
        credits: selectedPlan.credits
      }
    };

    const order = await razorpayInstance.orders.create(options);
    
    // Save transaction
    const transaction = new transactionModel({
      userId,
      orderId: order.id,
      plan: selectedPlan.name,
      amount: selectedPlan.amount,
      credits: selectedPlan.credits,
      status: 'created'
    });
    await transaction.save();

    res.status(200).json({
      success: true,
      order: {
        ...order,
        amount: order.amount / 100 // Convert back to rupees
      },
      plan: selectedPlan
    });

  } catch (error) {
    console.error("Order Error:", error);
    res.status(500).json({
      success: false,
      message: "Order creation failed",
      code: "ORDER_FAILED",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const verifyPayment = async (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid payment signature",
        code: "INVALID_SIGNATURE"
      });
    }

    const transaction = await transactionModel.findOne({ orderId: razorpay_order_id });
    if (!transaction) {
      return res.status(404).json({ 
        success: false, 
        message: "Transaction not found",
        code: "TRANSACTION_NOT_FOUND"
      });
    }

    if (transaction.status === 'completed') {
      return res.status(400).json({ 
        success: false, 
        message: "Payment already processed",
        code: "DUPLICATE_PAYMENT"
      });
    }

    const user = await userModel.findByIdAndUpdate(
      transaction.userId,
      { $inc: { creditBalance: transaction.credits } },
      { new: true }
    ).select("-password");

    transaction.status = 'completed';
    transaction.paymentId = razorpay_payment_id;
    transaction.signature = razorpay_signature;
    transaction.completedAt = new Date();
    await transaction.save();

    res.status(200).json({
      success: true,
      message: "Payment verified successfully",
      credits: user.creditBalance,
      user: sanitizeUser(user)
    });

  } catch (error) {
    console.error("Payment Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Payment verification failed",
      code: "PAYMENT_VERIFICATION_FAILED",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const getTransactions = async (req, res) => {
  try {
    const transactions = await transactionModel.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select("-__v -userId -signature");

    res.status(200).json({
      success: true,
      transactions
    });

  } catch (error) {
    console.error("Transactions Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to get transactions",
      code: "TRANSACTIONS_FETCH_FAILED",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const getUserCredits = async (req, res) => {
  try {
    const user = await userModel.findById(req.user.id).select('creditBalance');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
        code: "USER_NOT_FOUND"
      });
    }
    
    res.status(200).json({
      success: true,
      credits: user.creditBalance
    });
  } catch (error) {
    console.error("Get Credits Error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get credits",
      code: "CREDITS_FETCH_FAILED"
    });
  }
};