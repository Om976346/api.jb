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
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

// Course Schema
const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  lessons: { type: String, required: true },
  image: { type: String, required: true },
});

const Course = mongoose.model("Course", courseSchema);

// Topic Schema
const topicSchema = new mongoose.Schema({
  title: { type: String, required: true },
  duration: { type: String, required: true },
  youtubeLink: { type: String, required: true },
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
});

const Topic = mongoose.model("Topic", topicSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};

// Middleware to check if the user is an admin
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ message: "Access denied. Admin privileges required." });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// API Routes

// User Routes
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid password" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ token, isAdmin: user.isAdmin, message: "Sign-in successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId, { password: 0 });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Update User Profile
app.put("/api/user", authenticateToken, async (req, res) => {
  const { name, email } = req.body;

  try {
    // Find the user and update their profile
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (name) user.name = name;
    if (email) {
      const emailExists = await User.findOne({ email });
      if (emailExists && emailExists._id.toString() !== req.userId) {
        return res.status(400).json({ message: "Email already in use" });
      }
      user.email = email;
    }

    await user.save();

    res.status(200).json({ message: "Profile updated successfully", user });
  } catch (error) {
    res.status(500).json({ message: "Failed to update profile", error: error.message });
  }
});

// Course Routes
app.get("/api/courses", authenticateToken, async (req, res) => {
  try {
    const courses = await Course.find();
    res.status(200).json(courses);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/courses", authenticateToken, isAdmin, async (req, res) => {
  const { title, lessons, image } = req.body;

  try {
    if (!title || !lessons || !image) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const newCourse = new Course({ title, lessons, image });
    await newCourse.save();
    res.status(201).json(newCourse);
  } catch (error) {
    console.error("Error adding course:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.delete("/api/courses/:id", authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await Course.findByIdAndDelete(id);
    res.status(200).json({ message: "Course deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.get("/api/courses/search", authenticateToken, async (req, res) => {
  const { query } = req.query;

  try {
    if (!query) {
      return res.status(400).json({ message: "Search query is required" });
    }

    const courses = await Course.find({ title: { $regex: query, $options: "i" } });
    res.status(200).json(courses);
  } catch (error) {
    console.error("Error searching courses:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Topic Routes
app.get("/api/courses/:courseId/topics", authenticateToken, async (req, res) => {
  const { courseId } = req.params;

  try {
    const topics = await Topic.find({ courseId });
    res.status(200).json(topics);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.post("/api/courses/:courseId/topics", authenticateToken, isAdmin, async (req, res) => {
  const { courseId } = req.params;
  const { title, duration, youtubeLink } = req.body;

  try {
    if (!title || !duration || !youtubeLink) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const newTopic = new Topic({ title, duration, youtubeLink, courseId });
    await newTopic.save();
    res.status(201).json(newTopic);
  } catch (error) {
    console.error("Error adding topic:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.delete("/api/topics/:id", authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await Topic.findByIdAndDelete(id);
    res.status(200).json({ message: "Topic deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
