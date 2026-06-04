import { z } from "zod";

export const registerSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, "Username must be at least 3 characters."),
  email: z
    .string()
    .trim()
    .email("Please enter a valid email."),
  password: z
    .string()
    .min(6, "Password must be at least 6 characters."),
  address: z
    .string()
    .trim()
    .min(3, "Please enter your address."),
  phone: z
    .string()
    .trim()
    .regex(/^[0-9]{10}$/, "Phone must be 10 digits."),
  gender: z.enum(["male", "female", "other"], {
    message: "Please select your gender.",
  }),
});

export const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .email("Please enter a valid email."),
  password: z.string().min(1, "Please enter your password."),
});


