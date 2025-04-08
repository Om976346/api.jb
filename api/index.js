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
app.use(bodyParser.json({ limit: '10kb' })); // Limit body size to prevent DOS

// MongoDB Connection Optimization
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Maintain up to 10 socket connections
  serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
})
.then(() => console.log('MongoDB Connected'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1); // Exit process on connection failure
});

// Schema Definitions with Indexes
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true, select: false }, // Never return password in queries
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true }); // Add createdAt and updatedAt

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true }, // Index for faster search
  lessons: { type: String, required: true },
  image: { type: String, required: true },
}, { timestamps: true });

const topicSchema = new mongoose.Schema({
  title: { type: String, required: true },
  duration: { type: String, required: true },
  youtubeLink: { type: String, required: true },
  courseId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Course', 
    required: true,
    index: true // Index for faster queries
  },
}, { timestamps: true });

// Models
const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);
const Topic = mongoose.model('Topic', topicSchema);

// Middleware Optimization
const authenticateToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  // Verify token asynchronously to not block event loop
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.userId = decoded.id;
    next();
  });
};

const isAdmin = async (req, res, next) => {
  try {
    // Only select isAdmin field for efficiency
    const user = await User.findById(req.userId).select('isAdmin');
    if (!user?.isAdmin) {
      return res.status(403).json({ message: 'Admin privileges required.' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Response Handler Utility
const handleResponse = (res, status, message, data = null) => {
  const response = { message };
  if (data) response.data = data;
  return res.status(status).json(response);
};

// API Routes

// User Routes
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Input validation
    if (!name || !email || !password) {
      return handleResponse(res, 400, 'All fields are required');
    }

    // Check existing user using lean() for faster query
    const existingUser = await User.findOne({ email }).lean();
    if (existingUser) {
      return handleResponse(res, 400, 'User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, password: hashedPassword });
    
    handleResponse(res, 201, 'User created successfully', {
      id: newUser._id,
      name: newUser.name,
      email: newUser.email
    });
  } catch (error) {
    console.error('Signup error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return handleResponse(res, 400, 'Email and password are required');
    }

    // Select only necessary fields (+password for comparison)
    const user = await User.findOne({ email }).select('+password isAdmin');
    if (!user) {
      return handleResponse(res, 400, 'Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return handleResponse(res, 400, 'Invalid credentials');
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    handleResponse(res, 200, 'Sign-in successful', {
      token,
      isAdmin: user.isAdmin,
      name: user.name,
      email: user.email
    });
  } catch (error) {
    console.error('Signin error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    // Exclude password and other sensitive fields
    const user = await User.findById(req.userId)
      .select('-password -__v');
    
    if (!user) {
      return handleResponse(res, 404, 'User not found');
    }
    handleResponse(res, 200, 'User retrieved', user);
  } catch (error) {
    console.error('Get user error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.put('/api/user', authenticateToken, async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!name || !email) {
      return handleResponse(res, 400, 'Name and email are required');
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { name, email },
      { new: true, select: '-password -__v' } // Return updated doc without sensitive fields
    );

    if (!updatedUser) {
      return handleResponse(res, 404, 'User not found');
    }

    handleResponse(res, 200, 'Profile updated successfully', updatedUser);
  } catch (error) {
    console.error('Update user error:', error);
    handleResponse(res, 500, 'Failed to update profile');
  }
});

// Course Routes
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    // Use lean() for faster read-only operations
    const courses = await Course.find().lean();
    handleResponse(res, 200, 'Courses retrieved', courses);
  } catch (error) {
    console.error('Get courses error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.post('/api/courses', authenticateToken, isAdmin, async (req, res) => {
  const { title, lessons, image } = req.body;

  try {
    if (!title || !lessons || !image) {
      return handleResponse(res, 400, 'All fields are required');
    }

    const newCourse = await Course.create({ title, lessons, image });
    handleResponse(res, 201, 'Course created', newCourse);
  } catch (error) {
    console.error('Add course error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.delete('/api/courses/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const deletedCourse = await Course.findByIdAndDelete(req.params.id);
    if (!deletedCourse) {
      return handleResponse(res, 404, 'Course not found');
    }
    handleResponse(res, 200, 'Course deleted');
  } catch (error) {
    console.error('Delete course error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.get('/api/courses/search', authenticateToken, async (req, res) => {
  const { query } = req.query;

  try {
    if (!query || query.length < 3) {
      return handleResponse(res, 400, 'Search query must be at least 3 characters');
    }

    // Text search with index
    const courses = await Course.find({
      $text: { $search: query }
    }).lean();

    handleResponse(res, 200, 'Search results', courses);
  } catch (error) {
    console.error('Search error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

// Topic Routes
app.get('/api/courses/:courseId/topics', authenticateToken, async (req, res) => {
  try {
    const topics = await Topic.find({ courseId: req.params.courseId }).lean();
    handleResponse(res, 200, 'Topics retrieved', topics);
  } catch (error) {
    console.error('Get topics error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.post('/api/courses/:courseId/topics', authenticateToken, isAdmin, async (req, res) => {
  const { title, duration, youtubeLink } = req.body;

  try {
    if (!title || !duration || !youtubeLink) {
      return handleResponse(res, 400, 'All fields are required');
    }

    const newTopic = await Topic.create({
      title,
      duration,
      youtubeLink,
      courseId: req.params.courseId
    });

    handleResponse(res, 201, 'Topic created', newTopic);
  } catch (error) {
    console.error('Add topic error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

app.delete('/api/topics/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const deletedTopic = await Topic.findByIdAndDelete(req.params.id);
    if (!deletedTopic) {
      return handleResponse(res, 404, 'Topic not found');
    }
    handleResponse(res, 200, 'Topic deleted');
  } catch (error) {
    console.error('Delete topic error:', error);
    handleResponse(res, 500, 'Server error');
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  handleResponse(res, 500, 'Internal server error');
});

// Start Server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle graceful shutdown
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
