// src/routes/users.ts
import { Router } from 'express';
import {
  registerUser,
  loginUser,
  getCurrentUser,
  updateCurrentUser,
  deleteCurrentUser
} from '../controllers/users';
import { validateData } from '../middlewares/validationMiddleware'; // Middleware for Zod validation
import { verifyToken } from '../middlewares/authMiddleware';     // Middleware for JWT authentication
import { registerSchema, loginSchema, updateUserSchema } from '../validation/userValidation'; // Zod schemas

const router = Router();

// --- Public Routes (No authentication required) ---
// User registration: POST /api/auth/register
router.post('/register', validateData(registerSchema), registerUser);
// User login: POST /api/auth/login
router.post('/login', validateData(loginSchema), loginUser);

// --- Protected Routes (Authentication required via verifyToken middleware) ---
// Get current authenticated user's profile: GET /api/auth/me
router.get('/me', verifyToken, getCurrentUser);
// Update current authenticated user's profile: PUT /api/auth/me
router.put('/me', verifyToken, validateData(updateUserSchema), updateCurrentUser);
// Delete current authenticated user's account: DELETE /api/auth/me
router.delete('/me', verifyToken, deleteCurrentUser);

export default router;
