import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";


dotenv.config();

const app = express();
const PORT = process.env.PORT || 2004;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Course Schema
const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  lessons: { type: String, required: true },
  image: { type: String, required: true }, // Store CDN URL for the image
});

const Course = mongoose.model('Course', courseSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id; // Attach user ID to the request object
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// API Routes

// User Routes

// Sign-Up Route
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Sign-In Route
app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({ token, message: 'Sign-in successful' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get User Details by ID
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId, { password: 0 }); // Exclude password
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Course Routes

// Fetch all courses
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const courses = await Course.find();
    res.status(200).json(courses);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Add a new course
app.post('/api/courses', authenticateToken, async (req, res) => {
  const { title, lessons, image } = req.body;

  try {
    if (!title || !lessons || !image) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const newCourse = new Course({ title, lessons, image });
    await newCourse.save();
    res.status(201).json(newCourse);
  } catch (error) {
    console.error('Error adding course:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete a course
app.delete('/api/courses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    await Course.findByIdAndDelete(id);
    res.status(200).json({ message: 'Course deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Search for courses by title
app.get('/api/courses/search', authenticateToken, async (req, res) => {
  const { query } = req.query; // Get the search query from the request

  try {
    if (!query) {
      return res.status(400).json({ message: 'Search query is required' });
    }

    // Use a regex to perform a case-insensitive search
    const courses = await Course.find({ title: { $regex: query, $options: 'i' } });
    res.status(200).json(courses);
  } catch (error) {
    console.error('Error searching courses:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
