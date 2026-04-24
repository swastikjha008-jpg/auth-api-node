const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const JWT_SECRET = "secretkey";

app.use(express.json());

const users = [];

function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
}

app.get("/", (req, res) => {
  res.json({ message: "Auth API is running" });
});

app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const existingUser = users.find((user) => user.username === username);
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({
      username,
      password: hashedPassword,
    });

    return res.status(201).json({
      message: "Signup successful",
      username,
    });
  } catch (err) {
    return res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    const user = users.find((user) => user.username === username);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Wrong password" });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.json({
      message: "Login successful",
      token,
    });
  } catch (err) {
    return res.status(500).json({ message: "Something went wrong" });
  }
});

app.get("/me", auth, (req, res) => {
  const user = users.find((u) => u.username === req.user.username);

  return res.json({
    message: "Protected route accessed",
    user: user ? { username: user.username } : req.user,
  });
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});