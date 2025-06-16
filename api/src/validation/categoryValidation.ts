// src/validation/categoryValidation.ts
import { z } from 'zod';

// Schema untuk membuat kategori baru
export const createCategorySchema = z.object({
  name: z.string().min(1, 'Category name is required').trim(),
});

// Schema untuk memperbarui kategori
// Field 'name' opsional karena ini adalah update parsial
export const updateCategorySchema = z.object({
  name: z.string().min(1, 'Category name cannot be empty').trim().optional(),
}).refine(data => Object.keys(data).length > 0, {
  message: "At least one field (name) must be provided for update",
  path: ["body"],
});

// Export inferred types for convenience
export type CreateCategoryInput = z.infer<typeof createCategorySchema>;
export type UpdateCategoryInput = z.infer<typeof updateCategorySchema>;
