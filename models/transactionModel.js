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
    unique: true
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
    enum: ['pending', 'created', 'completed', 'failed'],
    default: 'pending'
  },
  paymentId: String,
  signature: String,
  razorpayOrder: Object
}, {
  timestamps: true
});

const transactionModel = mongoose.models.transaction || 
  mongoose.model("transaction", transactionSchema);

export default transactionModel;