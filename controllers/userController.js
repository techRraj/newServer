import userModel from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import validator from "validator";
import razorpay from "razorpay";
import transactionModel from "../models/transactionModel.js";
import crypto from "crypto";

// Initialize Razorpay
// const razorpayInstance = new razorpay({
//   key_id: process.env.RAZORPAY_KEY_ID,
//   key_secret: process.env.RAZORPAY_KEY_SECRET,
// });

/**
 * Register a new user
 */
const registerUser = async (req, res) => {
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

    // Check if user already exists
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

    // Create new user
    const newUser = new userModel({ 
      name, 
      email, 
      password: hashedPassword,
      creditBalance: 5 // Default credits
    });

    const user = await newUser.save();

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { 
      expiresIn: "1d" 
    });

    // Return response without password
    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(201).json({
      success: true,
      token,
      user: userResponse
    });

  } catch (error) {
    console.error("Register Error:", error.message);
    res.status(500).json({ 
      success: false, 
      message: "Registration failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * Login user
 */
const loginUser = async (req, res) => {
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

    // Return response without password
    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(200).json({
      success: true,
      token,
      user: userResponse
    });

  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ 
      success: false, 
      message: "Login failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * Get user credits
 */
const userCredits = async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await userModel.findById(userId).select("-password");
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    res.status(200).json({
      success: true,
      credits: user.creditBalance,
      user
    });

  } catch (error) {
    console.error("Credits Error:", error.message);
    res.status(500).json({ 
      success: false, 
      message: "Failed to get user credits",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * Initiate Razorpay payment
 */
const paymentRazorpay = async (req, res) => {
  try {
    const { planId } = req.body;
    const userId = req.user.id;

    if (!planId) {
      return res.status(400).json({ 
        success: false, 
        message: "Plan ID is required" 
      });
    }

    // Define plans
    const plans = {
      basic: { name: "Basic", credits: 25, amount: 10 },
      advanced: { name: "Advanced", credits: 70, amount: 30 },
      premier: { name: "Premier", credits: 150, amount: 50 }
    };

    const selectedPlan = plans[planId.toLowerCase()];
    if (!selectedPlan) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid plan selected" 
      });
    }

    // Create transaction record
    const transactionData = {
      userId,
      plan: selectedPlan.name,
      amount: selectedPlan.amount,
      credits: selectedPlan.credits,
      date: Date.now(),
    };

    const newTransaction = await transactionModel.create(transactionData);

    // Create Razorpay order
    const options = {
      amount: selectedPlan.amount * 100, // in paise
      currency: process.env.CURRENCY || "INR",
      receipt: newTransaction._id.toString(),
      payment_capture: 1
    };

    razorpayInstance.orders.create(options, (error, order) => {
      if (error) {
        console.error("Razorpay Error:", error);
        return res.status(400).json({ 
          success: false, 
          message: "Payment initialization failed" 
        });
      }
      
      res.status(200).json({ 
        success: true, 
        order,
        transactionId: newTransaction._id
      });
    });

  } catch (error) {
    console.error("Payment Error:", error.message);
    res.status(500).json({ 
      success: false, 
      message: "Payment processing failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

/**
 * Verify Razorpay payment
 */
const verifyRazorpay = async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, transactionId } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !transactionId) {
      return res.status(400).json({ 
        success: false, 
        message: "Payment verification failed - missing details" 
      });
    }

    // Verify signature
    const generatedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({ 
        success: false, 
        message: "Payment verification failed - invalid signature" 
      });
    }

    // Find transaction
    const transaction = await transactionModel.findById(transactionId);
    if (!transaction) {
      return res.status(404).json({ 
        success: false, 
        message: "Transaction not found" 
      });
    }

    if (transaction.payment) {
      return res.status(400).json({ 
        success: false, 
        message: "Payment already verified" 
      });
    }

    // Update user credits
    const user = await userModel.findByIdAndUpdate(
      transaction.userId,
      { $inc: { creditBalance: transaction.credits } },
      { new: true }
    );

    // Update transaction status
    transaction.payment = true;
    transaction.razorpayOrderId = razorpay_order_id;
    transaction.razorpayPaymentId = razorpay_payment_id;
    transaction.razorpaySignature = razorpay_signature;
    await transaction.save();

    res.status(200).json({
      success: true,
      message: "Payment verified successfully",
      credits: user.creditBalance
    });

  } catch (error) {
    console.error("Verification Error:", error.message);
    res.status(500).json({ 
      success: false, 
      message: "Payment verification failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export { 
  registerUser, 
  loginUser, 
  userCredits, 
  paymentRazorpay, 
  verifyRazorpay 
};