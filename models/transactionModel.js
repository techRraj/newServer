import mongoose from "mongoose";

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  orderId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  plan: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  credits: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['created', 'pending', 'completed', 'failed'],
    default: 'created'
  },
  paymentId: String,
  signature: String,
  receipt: String,
  razorpayOrder: Object // Store complete Razorpay order details
}, {
  timestamps: true
});

// Compound index for faster queries
transactionSchema.index({ orderId: 1, userId: 1 });

const transactionModel = mongoose.models.transaction || 
  mongoose.model("transaction", transactionSchema);

export default transactionModel;