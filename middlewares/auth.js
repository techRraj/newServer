import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';

const authUser = async (req, res, next) => {
  try {
    // Check for token in Authorization header or cookies
    let token = req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: "Authentication required" 
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user still exists
    const user = await userModel.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: "User no longer exists" 
      });
    }

    // Check if user changed password after token was issued
    if (user.passwordChangedAt && decoded.iat < user.passwordChangedAt.getTime() / 1000) {
      return res.status(401).json({ 
        success: false, 
        message: "Password was changed. Please log in again." 
      });
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication Error:', error.message);
    
    let message = "Invalid authentication";
    if (error.name === 'TokenExpiredError') {
      message = "Session expired. Please log in again.";
    } else if (error.name === 'JsonWebTokenError') {
      message = "Invalid token. Please log in again.";
    }

    return res.status(401).json({ 
      success: false, 
      message 
    });
  }
};

export default authUser;