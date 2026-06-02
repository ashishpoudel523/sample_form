const express = require("express");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const JWT_SECRET = "my-secret-key-change-in-real-project";
const USERS_FILE = path.join(__dirname, "data", "users.json");


function readUsers() {
  const data = fs.readFileSync(USERS_FILE, "utf-8");
  return JSON.parse(data);
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  return /^[0-9]{10}$/.test(phone);
}

// Register new user
app.post("/api/register", async (req, res) => {
  const { username, email, password, address, phone, gender } = req.body;

  if (!username || username.trim().length < 3) {
    return res.status(400).json({ message: "Username must be at least 3 characters." });
  }

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Please enter a valid email." });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters." });
  }

  if (!address || address.trim().length < 3) {
    return res.status(400).json({ message: "Please enter your address." });
  }

  if (!phone || !isValidPhone(phone)) {
    return res.status(400).json({ message: "Phone must be 10 digits." });
  }

  if (!gender) {
    return res.status(400).json({ message: "Please select your gender." });
  }

  const users = readUsers();
  const emailExists = users.find((user) => user.email === email.toLowerCase());

  if (emailExists) {
    return res.status(400).json({ message: "Email is already registered." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(),
    username: username.trim(),
    email: email.toLowerCase().trim(),
    password: hashedPassword,
    address: address.trim(),
    phone: phone.trim(),
    gender,
  };

  users.push(newUser);
  saveUsers(users);

  res.status(201).json({ message: "Registration successful! You can login now." });
});

// Login user
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Please enter a valid email." });
  }

  if (!password) {
    return res.status(400).json({ message: "Please enter your password." });
  }

  const users = readUsers();
  const user = users.find((item) => item.email === email.toLowerCase().trim());

  if (!user) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, username: user.username },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful!",
    token,
    user: {
      username: user.username,
      email: user.email,
    },
  });
});

// Protected route example (shows JWT works)
app.get("/api/profile", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: "Welcome!", user: decoded });
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
});

app.listen(PORT, () => {
  console.log("Server running at http://localhost:" + PORT);
});
