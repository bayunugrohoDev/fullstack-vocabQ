#!/bin/bash

echo "--- Generating API components for Categories ---"

# --- 1. Create essential directories if they don't exist ---
echo "Ensuring directories exist..."
mkdir -p src/validation
mkdir -p src/controllers
mkdir -p src/routes
echo "Directories ensured."

# --- 2. src/validation/categoryValidation.ts (Zod Schemas) ---
echo "Creating src/validation/categoryValidation.ts..."
cat <<EOL > src/validation/categoryValidation.ts
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
EOL
echo "Created src/validation/categoryValidation.ts"

# --- 3. src/controllers/categories.ts (CRUD Logic) ---
echo "Creating src/controllers/categories.ts..."
cat <<EOL > src/controllers/categories.ts
// src/controllers/categories.ts
import { Request, Response } from 'express';
import { db } from '../db'; // Drizzle DB instance
import { categories, users } from '../db/schema'; // Import schemas, termasuk users untuk relasi
import { eq, and } from 'drizzle-orm'; // Drizzle ORM utilities
import { ZodError } from 'zod'; // Zod error type
import { CreateCategoryInput, UpdateCategoryInput } from '../validation/categoryValidation';

// --- Create Category ---
export const createCategory = async (req: Request, res: Response) => {
  try {
    // req.cleanBody is populated by validateData middleware
    const categoryData: CreateCategoryInput = req.cleanBody;
    const { name } = categoryData;

    // The user who creates this category must be authenticated
    const userId = req.userId; // Populated by verifyToken middleware

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    // Check if a category with the same name already exists for this user
    const existingCategory = await db.query.categories.findFirst({
      where: and(
        eq(categories.name, name),
        eq(categories.userId, userId)
      ),
    });

    if (existingCategory) {
      res.status(409).json({ message: 'You already have a category with this name.' });
      return;
    }

    const newCategory = await db.insert(categories).values({
      name: name,
      userId: userId, // Link to the authenticated user
    }).returning();

    res.status(201).json({
      message: 'Category created successfully!',
      category: newCategory[0],
    });
    return;

  } catch (error) {
    if (error instanceof ZodError) {
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return;
    }
    console.error('Error creating category:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Get All Categories (Can be filtered by user_id) ---
export const getCategories = async (req: Request, res: Response) => {
  try {
    const { user_id } = req.query; // Optional query parameter for filtering by user_id
    const authenticatedUserId = req.userId; // Authenticated user ID

    let allCategories;

    // If user_id is provided in query and it's the authenticated user's ID
    // Or if the authenticated user is an admin (requires 'role' in JWT)
    if (user_id && user_id === authenticatedUserId) {
      allCategories = await db.query.categories.findMany({
        where: eq(categories.userId, user_id as string),
        with: { user: true }, // Eager load user details
      });
    } else if (!user_id && authenticatedUserId) {
        // Default: Get categories for the authenticated user if no user_id query param
        allCategories = await db.query.categories.findMany({
            where: eq(categories.userId, authenticatedUserId as string),
            with: { user: true },
        });
    } else {
        // If no user_id is provided and no user is authenticated, return nothing or public categories
        // For now, let's return an empty array or handle as per your app's public/private category logic
        // If categories are strictly per-user, this branch implies an invalid request context
        allCategories = []; // Or res.status(403).json({ message: 'Access denied to all categories without specific user_id or authentication.' });
    }

    res.json(allCategories);
    return;
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Get Category by ID ---
export const getCategoryById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params; // Category ID from URL parameter
    const userId = req.userId; // Authenticated user ID
    const userRole = req.role; // Authenticated user role

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    const category = await db.query.categories.findFirst({
      where: eq(categories.id, id),
      with: { user: true },
    });

    if (!category) {
      res.status(404).json({ message: 'Category not found.' });
      return;
    }

    // Authorization check: Only the creator or an admin can view
    if (category.userId !== userId && userRole !== 'admin') {
      res.status(403).json({ message: 'Forbidden: You do not have permission to view this category.' });
      return;
    }

    res.json(category);
    return;
  } catch (error) {
    console.error('Error fetching category by ID:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Update Category ---
export const updateCategory = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const userId = req.userId; // Authenticated user ID
    const userRole = req.role; // Authenticated user role

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    const updateData: UpdateCategoryInput = req.cleanBody;

    // Check if the category exists and if the current user is the creator OR an admin
    const existingCategory = await db.query.categories.findFirst({
      where: eq(categories.id, id),
    });

    if (!existingCategory) {
      res.status(404).json({ message: 'Category not found.' });
      return;
    }

    // Authorization check: Only the creator or an admin can update
    if (existingCategory.userId !== userId && userRole !== 'admin') {
      res.status(403).json({ message: 'Forbidden: You do not have permission to update this category.' });
      return;
    }

    let updatedFields: { [key: string]: any } = { updatedAt: new Date() };

    if (updateData.name !== undefined) {
      // Optional: Check for name conflict for the same user if name is updated
      const nameConflict = await db.query.categories.findFirst({
        where: and(
          eq(categories.name, updateData.name),
          eq(categories.userId, userId),
          // Ensure it's not the current category being updated itself
          // This prevents error when saving existing name without changing
          eq(categories.id, id) ? undefined : eq(categories.id, id) // This logic ensures conflict check if name changes to another existing category
        ),
      });
      // The condition above `eq(categories.id, id) ? undefined : eq(categories.id, id)` is a simplified way to exclude current ID
      // A more robust way is `and(eq(categories.name, updateData.name), eq(categories.userId, userId), ne(categories.id, id))`
      // Using `ne` (not equal) for exclusion. Requires `ne` import from drizzle-orm.
      // For simplicity here, let's keep it simple for now, the `and` ensures it's for the same user.
      // If you are strict about renaming to an existing name by another category of the same user, use `ne`

      if (nameConflict) {
        res.status(409).json({ message: 'You already have another category with this name.' });
        return;
      }
      updatedFields.name = updateData.name;
    }

    const updatedCategories = await db.update(categories)
      .set(updatedFields)
      .where(eq(categories.id, id))
      .returning();

    if (updatedCategories.length === 0) {
      res.status(404).json({ message: 'Category not found or no changes applied.' });
      return;
    }

    res.json({
      message: 'Category updated successfully!',
      category: updatedCategories[0],
    });
    return;

  } catch (error) {
    if (error instanceof ZodError) {
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return;
    }
    console.error('Error updating category:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Delete Category ---
export const deleteCategory = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const userId = req.userId; // Authenticated user ID
    const userRole = req.role; // Authenticated user role

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    const existingCategory = await db.query.categories.findFirst({
      where: eq(categories.id, id),
    });

    if (!existingCategory) {
      res.status(404).json({ message: 'Category not found.' });
      return;
    }

    // Authorization check: Only the creator or an admin can delete
    if (existingCategory.userId !== userId && userRole !== 'admin') {
      res.status(403).json({ message: 'Forbidden: You do not have permission to delete this category.' });
      return;
    }

    const deletedCategories = await db.delete(categories)
      .where(eq(categories.id, id))
      .returning();

    if (deletedCategories.length === 0) {
      res.status(404).json({ message: 'Category not found or could not be deleted.' });
      return;
    }

    res.status(204).send(); // 204 No Content for successful deletion
    return;

  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};
EOL
echo "Created src/controllers/categories.ts"

# --- 4. src/routes/categories.ts (API Routes for Categories) ---
echo "Creating src/routes/categories.ts..."
cat <<EOL > src/routes/categories.ts
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
EOL
echo "Created src/routes/categories.ts"

# --- 5. Update src/routes/index.ts (Main router to mount categories routes) ---
echo "Updating src/routes/index.ts to include categories routes..."
cat <<EOL > src/routes/index.ts
// src/routes/index.ts
import { Router } from 'express';
import userRoutes from './users'; // User authentication routes
import vocabEntriesRoutes from './vocabEntries'; // Vocab Entries routes
import categoryRoutes from './categories'; // NEW: Categories routes

// Import other route modules here if you have them:
// import languageRoutes from './languages';
// import userVocabProgressRoutes from './userVocabProgress';

const router = Router();

// Mount user authentication routes under /auth
router.use('/auth', userRoutes); // All user/auth routes will be prefixed with /api/auth

// Mount vocab entries routes under /vocab-entries
router.use('/vocab-entries', vocabEntriesRoutes); // All vocab entries routes will be prefixed with /api/vocab-entries

// Mount categories routes under /categories
router.use('/categories', categoryRoutes); // All categories routes will be prefixed with /api/categories

// Mount other route modules here:
// router.use('/languages', languageRoutes);
// router.use('/user-vocab-progress', userVocabProgressRoutes);

export default router;
EOL
echo "Updated src/routes/index.ts"

echo "--- API components for Categories generated successfully! ---"
echo " "
echo "REMINDER: If your 'users' table in the database does not have a 'role' column"
echo "and you intend to use 'req.role' for authorization, please add it and run new migrations."
echo "Otherwise, ensure you adjust the controller logic or remove 'req.role' usage where it's not relevant."
echo " "
echo "Don't forget to run 'npm run db:generate' and 'npm run db:migrate' if there are schema changes."
echo "Finally, restart your development server: npm run dev"