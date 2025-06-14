// src/validation/userValidation.ts
import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().min(1, 'Name is required').trim(),
  email: z.string().email('Invalid email address').toLowerCase().trim(),
  password: z.string().min(6, 'Password must be at least 6 characters long'),
  // current_language_id can be optional and nullable if user doesn't pick one during registration
  current_language_id: z.string().uuid('Invalid language ID format').optional().nullable(),
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email address').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required'), // Password length validation can be more relaxed for login
});

export const updateUserSchema = z.object({
  name: z.string().min(1, 'Name cannot be empty').trim().optional(),
  email: z.string().email('Invalid email address').toLowerCase().trim().optional(),
  password: z.string().min(6, 'Password must be at least 6 characters long').optional(),
  current_language_id: z.string().uuid('Invalid language ID format').optional().nullable(),
}).refine(data => Object.keys(data).length > 0, {
  message: "At least one field (name, email, password, current_language_id) must be provided for update",
  path: ["body"], // Zod error path
});

// Export inferred types for convenience
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
