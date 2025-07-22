import express from "express";
import cors from 'cors';
import 'dotenv/config';
import connectDB from "./config/mongodb.js";
import imageRouter from "./routes/imageRoutes.js";
import userRouter from "./routes/userRoutes.js";

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());

// CORS Setup
app.use(cors({
  origin: 'https://tech-rraj-client-repo.vercel.app ',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'token']
}));

// Connect DB
await connectDB();

// Routes
app.use('/api/user', userRouter);
app.use('/api/image', imageRouter);

// Health check
app.get('/', (req, res) => {
  res.send('API Working');
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server started on PORT:${port}`);
});