import mongoose from "mongoose";

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  orderId: {
    type: String,
    required: false, // Changed from true to false initially
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

// Remove the separate index() call since we already have unique: true in schema
// transactionSchema.index({ orderId: 1 }, { unique: true }); // REMOVE THIS LINE

// Safe model registration
let Transaction;
if (mongoose.models.Transaction) {
  Transaction = mongoose.model('Transaction');
} else {
  Transaction = mongoose.model('Transaction', transactionSchema);
}

export default Transaction;