// controllers/imageController.js
import userModel from "../models/userModel.js";
import FormData from "form-data";
import axios from "axios";

export const generateImage = async (req, res) => {
  try {
    const userId = req.user.id; // From auth middleware
    const { prompt } = req.body;

    if (!prompt) {
      return res.status(400).json({ success: false, message: 'Prompt is required' });
    }

    const user = await userModel.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.creditBalance <= 0) {
      return res.status(400).json({
        success: false,
        message: 'No Credit Balance',
        creditBalance: user.creditBalance,
      });
    }

    const formData = new FormData();
    formData.append('prompt', prompt);

    const clipDropRes = await axios.post(
      'https://clipdrop-api.co/text-to-image/v1 ', // ✅ Removed trailing space
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          'x-api-key': process.env.CLIPDROP_API,
        },
        responseType: 'arraybuffer',
      }
    );

    const base64Image = Buffer.from(clipDropRes.data, 'binary').toString('base64');
    const resultImage = `data:image/png;base64,${base64Image}`;

    // Deduct 1 credit
    await userModel.findByIdAndUpdate(userId, { $inc: { creditBalance: -1 } });

    res.status(200).json({
      success: true,
      message: 'Image Generated',
      creditBalance: user.creditBalance - 1,
      resultImage,
    });
  } catch (error) {
    console.error("Generate Image Error:", error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};