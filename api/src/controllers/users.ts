// src/controllers/users.ts
import { Request, Response } from 'express';
import { db } from '../db';
import { users, languages } from '../db/schema';
import { eq } from 'drizzle-orm';
import bcrypt from 'bcryptjs';
import { generateToken } from '../utils/jwt';
import { registerSchema, loginSchema, updateUserSchema } from '../validation/userValidation';
import { ZodError } from 'zod';

// --- User Registration ---
export const registerUser = async (req: Request, res: Response) => {
  try {
    const userData = registerSchema.parse(req.cleanBody);
    const { name, email, password, current_language_id } = userData;

    const existingUser = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    if (existingUser) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(409).json({ message: 'Email already registered.' });
      return; // Cukup 'return;' untuk keluar dari fungsi async
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await db.insert(users).values({
      name,
      email,
      password: hashedPassword,
      currentLanguageId: current_language_id || null,
    }).returning();

    const { password: userPassword, ...userWithoutPassword } = newUser[0];
    const token = generateToken({
      userId: userWithoutPassword.id,
      email: userWithoutPassword.email,
    });

    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(201).json({
      message: 'User registered successfully!',
      user: userWithoutPassword,
      token,
    });
    return; // Cukup 'return;' untuk keluar dari fungsi async setelah mengirim respons

  } catch (error) {
    if (error instanceof ZodError) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return; // Cukup 'return;'
    }
    console.error('Error during user registration:', error);
    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(500).json({ message: 'Internal server error' });
    return; // Cukup 'return;'
  }
};

// --- User Login ---
export const loginUser = async (req: Request, res: Response) => {
  try {
    const { email, password } = loginSchema.parse(req.cleanBody);

    const user = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    if (!user) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(401).json({ message: 'Invalid credentials (email not found).' });
      return; // Cukup 'return;'
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(401).json({ message: 'Invalid credentials (password mismatch).' });
      return; // Cukup 'return;'
    }

    const { password: userPassword, ...userWithoutPassword } = user;
    const token = generateToken({
      userId: userWithoutPassword.id,
      email: userWithoutPassword.email,
    });

    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(200).json({
      message: 'Login successful!',
      token,
      user: userWithoutPassword,
    });
    return; // Cukup 'return;'

  } catch (error) {
    if (error instanceof ZodError) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return; // Cukup 'return;'
    }
    console.error('Error during login:', error);
    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(500).json({ message: 'Internal server error' });
    return; // Cukup 'return;'
  }
};

// --- Get Current Authenticated User's Profile ---
export const getCurrentUser = async (req: Request, res: Response) => {
  try {
    const userId = req.userId;

    if (!userId) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(401).json({ message: 'User not authenticated or ID missing.' });
      return; // Cukup 'return;'
    }

    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        currentLanguage: true,
      },
    });

    if (!user) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(404).json({ message: 'User not found.' });
      return; // Cukup 'return;'
    }

    const { password: userPassword, ...userWithoutPassword } = user;
    // === PENTING: Hapus 'return' di depan res.json() ===
    res.json(userWithoutPassword);
    return; // Cukup 'return;'

  } catch (error) {
    console.error('Error fetching current user:', error);
    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(500).json({ message: 'Internal server error' });
    return; // Cukup 'return;'
  }
};

// --- Update Current Authenticated User's Profile ---
export const updateCurrentUser = async (req: Request, res: Response) => {
  try {
    const userId = req.userId;
    if (!userId) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(401).json({ message: 'User not authenticated.' });
      return; // Cukup 'return;'
    }

    const updateData = updateUserSchema.parse(req.cleanBody);

    let updatedFields: { [key: string]: any } = { updatedAt: new Date() };

    if (updateData.name !== undefined) updatedFields.name = updateData.name;
    if (updateData.email !== undefined) {
        const existingUserWithEmail = await db.query.users.findFirst({
            where: eq(users.email, updateData.email),
        });
        if (existingUserWithEmail && existingUserWithEmail.id !== userId) {
            // === PENTING: Hapus 'return' di depan res.status() ===
            res.status(409).json({ message: 'Email already taken by another user.' });
            return; // Cukup 'return;'
        }
        updatedFields.email = updateData.email;
    }
    if (updateData.password !== undefined) updatedFields.password = await bcrypt.hash(updateData.password, 10);
    if (updateData.current_language_id !== undefined) updatedFields.currentLanguageId = updateData.current_language_id;


    const updatedUsers = await db.update(users)
      .set(updatedFields)
      .where(eq(users.id, userId))
      .returning();

    if (updatedUsers.length === 0) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(404).json({ message: 'User not found or nothing to update.' });
      return; // Cukup 'return;'
    }

    const { password: userPassword, ...userWithoutPassword } = updatedUsers[0];
    // === PENTING: Hapus 'return' di depan res.json() ===
    res.json(userWithoutPassword);
    return; // Cukup 'return;'

  } catch (error) {
    if (error instanceof ZodError) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return; // Cukup 'return;'
    }
    console.error('Error updating user profile:', error);
    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(500).json({ message: 'Internal server error' });
    return; // Cukup 'return;'
  }
};

// --- Delete Current Authenticated User's Account ---
export const deleteCurrentUser = async (req: Request, res: Response) => {
  try {
    const userId = req.userId;
    if (!userId) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(401).json({ message: 'User not authenticated.' });
      return; // Cukup 'return;'
    }

    const deletedUsers = await db.delete(users)
      .where(eq(users.id, userId))
      .returning();

    if (deletedUsers.length === 0) {
      // === PENTING: Hapus 'return' di depan res.status() ===
      res.status(404).json({ message: 'User not found.' });
      return; // Cukup 'return;'
    }

    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(204).send(); // No content
    return; // Cukup 'return;'
  } catch (error) {
    console.error('Error deleting user account:', error);
    // === PENTING: Hapus 'return' di depan res.status() ===
    res.status(500).json({ message: 'Internal server error' });
    return; // Cukup 'return;'
  }
};