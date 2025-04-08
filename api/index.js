import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 2004;

// Middleware
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => {
    console.error("Database Connection Error: ", err.message);
    process.exit(1);
  });

// Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  lessons: { type: String, required: true },
  image: { type: String, required: true },
});

const Course = mongoose.model("Course", courseSchema);

const topicSchema = new mongoose.Schema({
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
  title: { type: String, required: true },
  duration: { type: String, required: true },
  youtubeLink: { type: String, required: true },
});

const Topic = mongoose.model("Topic", topicSchema);

// Utility Functions
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided." });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token." });
    req.userId = decoded.id;
    next();
  });
};

const isAdmin = async (req, res, next) => {
  const user = await User.findById(req.userId).lean();
  if (!user?.isAdmin) return res.status(403).json({ message: "Admin access required." });
  next();
};

// ---------- API Routes ----------

// User Routes
app.post(
  "/api/signup",
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const userExists = await User.exists({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({ name, email, password: hashedPassword });

    res.status(201).json({ message: "User created successfully", userId: newUser._id });
  })
);

app.post(
  "/api/signin",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ token, isAdmin: user.isAdmin, message: "Sign-in successful." });
  })
);

app.get(
  "/api/user",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.userId, "-password").lean();
    if (!user) return res.status(404).json({ message: "User not found." });

    res.status(200).json(user);
  })
);

app.put(
  "/api/user",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { name, email } = req.body;

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (email) {
      const emailExists = await User.findOne({ email });
      if (emailExists && emailExists._id.toString() !== req.userId) {
        return res.status(400).json({ message: "Email already in use." });
      }
      user.email = email;
    }
    user.name = name || user.name;

    await user.save();
    res.status(200).json({ message: "Profile updated successfully." });
  })
);

// Course Routes
app.get(
  "/api/courses",
  authenticateToken,
  asyncHandler(async (_, res) => {
    const courses = await Course.find().lean();
    res.status(200).json(courses);
  })
);

app.post(
  "/api/courses",
  authenticateToken,
  isAdmin,
  asyncHandler(async (req, res) => {
    const { title, lessons, image } = req.body;

    const course = await Course.create({ title, lessons, image });
    res.status(201).json(course);
  })
);

app.delete(
  "/api/courses/:id",
  authenticateToken,
  isAdmin,
  asyncHandler(async (req, res) => {
    await Course.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: "Course deleted successfully." });
  })
);

app.get(
  "/api/courses/search",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const { query } = req.query;
    if (!query) return res.status(400).json({ message: "Search query required." });

    const courses = await Course.find({
      title: { $regex: query, $options: "i" },
    }).lean();

    res.status(200).json(courses);
  })
);

// Topic Routes
app.get(
  "/api/courses/:courseId/topics",
  authenticateToken,
  asyncHandler(async (req, res) => {
    const topics = await Topic.find({ courseId: req.params.courseId }).lean();
    res.status(200).json(topics);
  })
);

app.post(
  "/api/courses/:courseId/topics",
  authenticateToken,
  isAdmin,
  asyncHandler(async (req, res) => {
    const { courseId } = req.params;
    const { title, duration, youtubeLink } = req.body;

    const topic = await Topic.create({ courseId, title, duration, youtubeLink });
    res.status(201).json(topic);
  })
);

app.delete(
  "/api/topics/:id",
  authenticateToken,
  isAdmin,
  asyncHandler(async (req, res) => {
    await Topic.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: "Topic deleted successfully." });
  })
);

// ---------- Error Handling Middleware ----------
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "An error occurred.", error: err.message });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
