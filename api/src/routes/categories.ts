// src/routes/categories.ts
import { Router } from 'express';
import {
  createCategory,
  getCategories,
  getCategoryById,
  updateCategory,
  deleteCategory,
} from '../controllers/categories';
import { validateData } from '../middlewares/validationMiddleware'; // Zod validation middleware
import { verifyToken, authorizeRoles } from '../middlewares/authMiddleware'; // Auth middleware

import { createCategorySchema, updateCategorySchema } from '../validation/categoryValidation'; // Zod schemas

const router = Router();

// --- Protected Routes (Authentication Required) ---

// Create a new category: POST /api/categories
router.post('/', verifyToken, validateData(createCategorySchema), createCategory);

// Get all categories (can be filtered by user_id): GET /api/categories
router.get('/', verifyToken, getCategories);

// Get a specific category by ID: GET /api/categories/:id
router.get('/:id', verifyToken, getCategoryById);

// Update a category by ID: PUT /api/categories/:id
// Only creator or admin can update
router.put('/:id', verifyToken, validateData(updateCategorySchema), updateCategory);

// Delete a category by ID: DELETE /api/categories/:id
// Only creator or admin can delete
router.delete('/:id', verifyToken, deleteCategory);

export default router;
