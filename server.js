import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "path";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";
import { registerSchema, loginSchema } from "./validators/validatorSchema.js";
import { prisma } from "./lib/prisma.js";

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

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/register", async (req, res) => {
  const result = registerSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json(zodValidationError(result.error));
  }

  const { username, email, password, address, phone, gender } = result.data;

  try {
    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (existingUser) {
      return res.status(400).json({ message: "Email is already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.user.create({
      data: {
        username,
        email: email.toLowerCase(),
        password: hashedPassword,
        address,
        phone,
        gender,
      },
    });

    res.status(201).json({ message: "Registration successful! You can login now." });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Something went wrong. Please try again." });
  }
});

app.post("/api/login", async (req, res) => {
  const result = loginSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json(zodValidationError(result.error));
  }

  const { email, password } = result.data;

  try {
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    res.json({
      message: "Login successful!",
      user: {
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Something went wrong. Please try again." });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
