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

// Utility function to remove sensitive data from user object
const sanitizeUser = (user) => {
  const userObj = user.toObject();
  delete userObj.password;
  delete userObj.__v;
  return userObj;
};

// User Controller Methods
export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "All fields are required" 
      });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: "Please enter a valid email" 
      });
    }

    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: "Password must be at least 8 characters" 
      });
    }

    // Check if user exists
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: "Email already registered" 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user with 5 free credits
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

    res.status(201).json({
      success: true,
      token,
      user: sanitizeUser(user)
    });

  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Registration failed",
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
        message: "Email and password are required" 
      });
    }

    // Find user with password
    const user = await userModel.findOne({ email }).select("+password");
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    // Generate token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { 
      expiresIn: "1d" 
    });

    res.status(200).json({
      success: true,
      token,
      user: sanitizeUser(user)
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Login failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const getUserProfile = async (req, res) => {
  try {
    const user = await userModel.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
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
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const updateUserProfile = async (req, res) => {
  try {
    const { name } = req.body;
    const user = await userModel.findByIdAndUpdate(
      req.user.id,
      { name },
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
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await userModel.findById(req.user.id).select("+password");

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false, 
        message: "Current password is incorrect" 
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
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const createOrder = async (req, res) => {
  try {
    const { planId } = req.body;
    const userId = req.user.id;

    const plans = {
      basic: { name: "Basic", credits: 25, amount: 1000 },
      standard: { name: "Standard", credits: 70, amount: 3000 },
      premium: { name: "Premium", credits: 150, amount: 5000 }
    };

    const selectedPlan = plans[planId];
    if (!selectedPlan) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid plan selected" 
      });
    }

    const options = {
      amount: selectedPlan.amount,
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
      order,
      plan: selectedPlan
    });

  } catch (error) {
    console.error("Order Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Order creation failed",
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
        message: "Invalid payment signature" 
      });
    }

    const transaction = await transactionModel.findOne({ orderId: razorpay_order_id });
    if (!transaction) {
      return res.status(404).json({ 
        success: false, 
        message: "Transaction not found" 
      });
    }

    if (transaction.status === 'completed') {
      return res.status(400).json({ 
        success: false, 
        message: "Payment already processed" 
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
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const getTransactions = async (req, res) => {
  try {
    const transactions = await transactionModel.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select("-__v -userId");

    res.status(200).json({
      success: true,
      transactions
    });

  } catch (error) {
    console.error("Transactions Error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to get transactions",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};