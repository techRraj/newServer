import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Name is required'],
    trim: true
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
      message: props => `${props.value} is not a valid email`
    }
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: 8,
    select: false
  },
  creditBalance: { 
    type: Number, 
    default: 5,
    min: 0
  },
  role: { 
    type: String, 
    enum: ['user', 'admin'],
    default: 'user'
  },
  transactions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  }]
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: (doc, ret) => {
      delete ret.password;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });

const userModel = mongoose.models.user || mongoose.model('user', userSchema);
export default userModel;