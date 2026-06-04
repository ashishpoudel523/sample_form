import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";
import { registerSchema, loginSchema } from "./validators/validatorSchema.js";

function zodValidationError(error) {
  const fieldErrors = {};
  for (const issue of error.issues) {
    const field = issue.path[0];
    if (field && !fieldErrors[field]) {
      fieldErrors[field] = issue.message;
    }
  }
  return {
    message: error.issues[0]?.message ?? "Validation failed.",
    fieldErrors,
  };
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET
const USERS_FILE = path.join(__dirname, "data", "users.json");

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function readUsers() {
  const data = fs.readFileSync(USERS_FILE, "utf-8");
  return JSON.parse(data);
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

app.post("/api/register", async (req, res) => {
  const result = registerSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json(zodValidationError(result.error));
  }

  const { username, email, password, address, phone, gender } = result.data;

  const users = readUsers();
  const emailExists = users.find((user) => user.email === email.toLowerCase());

  if (emailExists) {
    return res.status(400).json({ message: "Email is already registered." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(),
    username,
    email: email.toLowerCase(),
    password: hashedPassword,
    address,
    phone,
    gender,
  };

  users.push(newUser);
  saveUsers(users);

  res.status(201).json({ message: "Registration successful! You can login now." });
});

app.post("/api/login", async (req, res) => {
  const result = loginSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json(zodValidationError(result.error));
  }

  const { email, password } = result.data;

  const users = readUsers();
  const user = users.find((item) => item.email === email.toLowerCase());

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
  console.log(`Server running at http://localhost:${PORT}`);
});
