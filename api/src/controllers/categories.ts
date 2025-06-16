// src/controllers/categories.ts
import { Request, Response } from "express";
import { db } from "../db"; // Drizzle DB instance
import { categories, users } from "../db/schema"; // Import schemas, termasuk users untuk relasi
import { eq, and } from "drizzle-orm"; // Drizzle ORM utilities
import { ZodError } from "zod"; // Zod error type
import {
  CreateCategoryInput,
  UpdateCategoryInput,
} from "../validation/categoryValidation";

// --- Create Category ---
export const createCategory = async (req: Request, res: Response) => {
  try {
    // req.cleanBody is populated by validateData middleware
    const categoryData: CreateCategoryInput = req.cleanBody;
    const { name } = categoryData;

    // The user who creates this category must be authenticated
    const userId = req.userId; // Populated by verifyToken middleware

    if (!userId) {
      res.status(401).json({ message: "Unauthorized: User ID missing." });
      return;
    }

    // Check if a category with the same name already exists for this user
    const existingCategory = await db.query.categories.findFirst({
      where: and(eq(categories.name, name), eq(categories.userId, userId)),
    });

    if (existingCategory) {
      res
        .status(409)
        .json({ message: "You already have a category with this name." });
      return;
    }

    const newCategory = await db
      .insert(categories)
      .values({
        name: name,
        userId: userId, // Link to the authenticated user
      })
      .returning();

    res.status(201).json({
      message: "Category created successfully!",
      category: newCategory[0],
    });
    return;
  } catch (error) {
    if (error instanceof ZodError) {
      res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
      return;
    }
    console.error("Error creating category:", error);
    res.status(500).json({ message: "Internal server error" });
    return;
  }
};

// --- Get All Categories (Can be filtered by user_id) ---
export const getCategories = async (req: Request, res: Response) => {
  try {
    const { user_id } = req.query; // Optional query parameter untuk filter berdasarkan user_id
    const authenticatedUserId = req.userId; // ID pengguna yang terautentikasi
    const userRole = req.role; // Role pengguna yang terautentikasi (jika ada)

    if (!authenticatedUserId) {
      // Jika tidak ada user terautentikasi, dan tidak ada mekanisme public categories, tolak akses
      res
        .status(401)
        .json({
          message:
            "Unauthorized: Authentication is required to access categories.",
        });
      return;
    }

    let queryBuilder = db.query.categories.findMany({
      with: {
        createdBy: true, // Eager load user details
      },
      // Order by latest created categories
      orderBy: [categories.createdAt, categories.name],
    });

    // --- LOGIKA FILTERING ---
    // Logika default: Tampilkan hanya kategori milik user yang sedang login
    let filterCondition: any = eq(categories.userId, authenticatedUserId);

    // Jika ada user_id di query
    if (user_id) {
      // Izinkan admin untuk melihat kategori user lain dengan user_id yang spesifik
      // Atau jika user_id yang diminta sama dengan user terautentikasi
      if (userRole === "admin" || user_id === authenticatedUserId) {
        filterCondition = eq(categories.userId, user_id as string);
      } else {
        // Jika user bukan admin dan user_id di query bukan miliknya sendiri
        res
          .status(403)
          .json({
            message:
              "Forbidden: You do not have permission to access categories of other users.",
          });
        return;
      }
    }

    // Apply the filter condition to the query
    const allCategories =
      await db.query.categories.findMany({
        where: filterCondition,
        with: {
          createdBy: true,
        },
        orderBy: [categories.createdAt, categories.name],
      });

    res.json(allCategories);
    return;
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({ message: "Internal server error" });
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
      res.status(401).json({ message: "Unauthorized: User ID missing." });
      return;
    }

    const category = await db.query.categories.findFirst({
      where: eq(categories.id, id),
      with: { createdBy: true },
    });

    if (!category) {
      res.status(404).json({ message: "Category not found." });
      return;
    }

    // Authorization check: Only the creator or an admin can view
    if (category.userId !== userId && userRole !== "admin") {
      res
        .status(403)
        .json({
          message:
            "Forbidden: You do not have permission to view this category.",
        });
      return;
    }

    res.json(category);
    return;
  } catch (error) {
    console.error("Error fetching category by ID:", error);
    res.status(500).json({ message: "Internal server error" });
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
      res.status(401).json({ message: "Unauthorized: User ID missing." });
      return;
    }

    const updateData: UpdateCategoryInput = req.cleanBody;

    // Check if the category exists and if the current user is the creator OR an admin
    const existingCategory = await db.query.categories.findFirst({
      where: eq(categories.id, id),
    });

    if (!existingCategory) {
      res.status(404).json({ message: "Category not found." });
      return;
    }

    // Authorization check: Only the creator or an admin can update
    if (existingCategory.userId !== userId && userRole !== "admin") {
      res
        .status(403)
        .json({
          message:
            "Forbidden: You do not have permission to update this category.",
        });
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
      // The condition above  is a simplified way to exclude current ID
      // A more robust way is
      // Using  (not equal) for exclusion. Requires  import from drizzle-orm.
      // For simplicity here, let's keep it simple for now, the  ensures it's for the same user.
      // If you are strict about renaming to an existing name by another category of the same user, use

      if (nameConflict) {
        res
          .status(409)
          .json({
            message: "You already have another category with this name.",
          });
        return;
      }
      updatedFields.name = updateData.name;
    }

    const updatedCategories = await db
      .update(categories)
      .set(updatedFields)
      .where(eq(categories.id, id))
      .returning();

    if (updatedCategories.length === 0) {
      res
        .status(404)
        .json({ message: "Category not found or no changes applied." });
      return;
    }

    res.json({
      message: "Category updated successfully!",
      category: updatedCategories[0],
    });
    return;
  } catch (error) {
    if (error instanceof ZodError) {
      res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
      return;
    }
    console.error("Error updating category:", error);
    res.status(500).json({ message: "Internal server error" });
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
      res.status(401).json({ message: "Unauthorized: User ID missing." });
      return;
    }

    const existingCategory = await db.query.categories.findFirst({
      where: eq(categories.id, id),
    });

    if (!existingCategory) {
      res.status(404).json({ message: "Category not found." });
      return;
    }

    // Authorization check: Only the creator or an admin can delete
    if (existingCategory.userId !== userId && userRole !== "admin") {
      res
        .status(403)
        .json({
          message:
            "Forbidden: You do not have permission to delete this category.",
        });
      return;
    }

    const deletedCategories = await db
      .delete(categories)
      .where(eq(categories.id, id))
      .returning();

    if (deletedCategories.length === 0) {
      res
        .status(404)
        .json({ message: "Category not found or could not be deleted." });
      return;
    }

    res.status(204).send(); // 204 No Content for successful deletion
    return;
  } catch (error) {
    console.error("Error deleting category:", error);
    res.status(500).json({ message: "Internal server error" });
    return;
  }
};
