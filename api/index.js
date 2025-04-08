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

// Enhanced Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10kb' })); // Limit payload size
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));

// MongoDB Connection with improved settings
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
  maxPoolSize: 50, // Increased connection pool size
})
.then(() => console.log('MongoDB Connected'))
.catch(err => {
  console.error('MongoDB Connection Error:', err);
  process.exit(1); // Exit process on connection failure
});

// Connection events for better error handling
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

// Schemas remain the same but with added indexes for performance
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true }, // Added index for search
  lessons: { type: String, required: true },
  image: { type: String, required: true },
});

const Course = mongoose.model('Course', courseSchema);

const topicSchema = new mongoose.Schema({
  title: { type: String, required: true },
  duration: { type: String, required: true },
  youtubeLink: { type: String, required: true },
  courseId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Course', 
    required: true,
    index: true // Added index for faster lookups
  },
});

const Topic = mongoose.model('Topic', topicSchema);

// Cache middleware for frequent GET requests
const cache = {};
const cacheMiddleware = (req, res, next) => {
  const key = req.originalUrl;
  if (cache[key] && Date.now() - cache[key].timestamp < 30000) { // 30s cache
    return res.json(cache[key].data);
  }
  res.sendResponse = res.json;
  res.json = (body) => {
    cache[key] = {
      timestamp: Date.now(),
      data: body
    };
    res.sendResponse(body);
  };
  next();
};

// Optimized JWT verification
const authenticateToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Optimized admin check
const isAdmin = async (req, res, next) => {
  try {
    // Only fetch the isAdmin field to minimize data transfer
    const user = await User.findById(req.userId, 'isAdmin');
    if (!user || !user.isAdmin) {
      return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
    }
    next();
  } catch (error) {
    console.error('Admin check error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// API Routes with optimizations

// User Routes
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  // Input validation
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    // Use lean() for faster query as we don't need mongoose document
    const existingUser = await User.findOne({ email }).lean();
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, password: hashedPassword });
    
    res.status(201).json({ 
      message: 'User created successfully',
      userId: newUser._id 
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    // Only select necessary fields
    const user = await User.findOne({ email })
      .select('password isAdmin')
      .lean();
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' }); // Generic message for security
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({ 
      token, 
      isAdmin: user.isAdmin, 
      message: 'Sign-in successful' 
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    // Exclude password and version key
    const user = await User.findById(req.userId, { password: 0, __v: 0 }).lean();
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Course Routes with caching
app.get('/api/courses', authenticateToken, cacheMiddleware, async (req, res) => {
  try {
    const courses = await Course.find().lean();
    res.status(200).json(courses);
  } catch (error) {
    console.error('Get courses error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/courses', authenticateToken, isAdmin, async (req, res) => {
  const { title, lessons, image } = req.body;

  if (!title || !lessons || !image) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const newCourse = await Course.create({ title, lessons, image });
    // Invalidate cache
    Object.keys(cache).forEach(key => {
      if (key.startsWith('/api/courses')) delete cache[key];
    });
    res.status(201).json(newCourse);
  } catch (error) {
    console.error('Add course error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/courses/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await Course.findByIdAndDelete(id);
    // Invalidate cache
    Object.keys(cache).forEach(key => {
      if (key.startsWith('/api/courses')) delete cache[key];
    });
    res.status(200).json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error('Delete course error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/courses/search', authenticateToken, async (req, res) => {
  const { query } = req.query;

  if (!query || query.length < 2) {
    return res.status(400).json({ message: 'Search query must be at least 2 characters' });
  }

  try {
    const courses = await Course.find({ 
      title: { $regex: query, $options: 'i' } 
    }).lean();
    res.status(200).json(courses);
  } catch (error) {
    console.error('Search courses error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Topic Routes
app.get('/api/courses/:courseId/topics', authenticateToken, cacheMiddleware, async (req, res) => {
  const { courseId } = req.params;

  try {
    const topics = await Topic.find({ courseId }).lean();
    res.status(200).json(topics);
  } catch (error) {
    console.error('Get topics error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/courses/:courseId/topics', authenticateToken, isAdmin, async (req, res) => {
  const { courseId } = req.params;
  const { title, duration, youtubeLink } = req.body;

  if (!title || !duration || !youtubeLink) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const newTopic = await Topic.create({ title, duration, youtubeLink, courseId });
    // Invalidate cache for this course's topics
    delete cache[`/api/courses/${courseId}/topics`];
    res.status(201).json(newTopic);
  } catch (error) {
    console.error('Add topic error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/topics/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const topic = await Topic.findByIdAndDelete(id).lean();
    if (!topic) {
      return res.status(404).json({ message: 'Topic not found' });
    }
    // Invalidate cache for this course's topics
    delete cache[`/api/courses/${topic.courseId}/topics`];
    res.status(200).json({ message: 'Topic deleted successfully' });
  } catch (error) {
    console.error('Delete topic error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});
