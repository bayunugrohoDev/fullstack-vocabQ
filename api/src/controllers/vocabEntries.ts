// src/controllers/vocabEntries.ts
import { Request, Response } from 'express';
import { db } from '../db'; // Drizzle DB instance
import { vocabEntries, languages, users } from '../db/schema'; // Import schemas, termasuk users dan languages untuk relasi
import { eq, and, or } from 'drizzle-orm'; // Drizzle ORM utilities
import { ZodError } from 'zod'; // Zod error type
import { CreateVocabEntryInput, UpdateVocabEntryInput } from '../validation/vocabEntryValidation';

// --- Create Vocab Entry ---
export const createVocabEntry = async (req: Request, res: Response) => {
  try {
    // req.cleanBody is populated by validateData middleware
    const vocabData: CreateVocabEntryInput = req.cleanBody;
    const { original_word, meaning, description, example_sentence, language_id } = vocabData;

    // The user who creates this entry should be authenticated
    const createdByUserId = req.userId; // Populated by verifyToken middleware

    if (!createdByUserId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    // Optional: Verify if the language_id exists in the languages table
    const languageExists = await db.query.languages.findFirst({
      where: eq(languages.id, language_id),
    });
    if (!languageExists) {
      res.status(400).json({ message: 'Invalid language_id provided.' });
      return;
    }

    // Check for existing vocab entry with the same original_word and language_id
    const existingVocabEntry = await db.query.vocabEntries.findFirst({
      where: and(
        eq(vocabEntries.originalWord, original_word),
        eq(vocabEntries.languageId, language_id)
      ),
    });

    if (existingVocabEntry) {
      res.status(409).json({ message: 'A vocabulary entry with this word and language already exists.' });
      return;
    }

    const newEntry = await db.insert(vocabEntries).values({
      originalWord: original_word,
      meaning: meaning,
      description: description,
      exampleSentence: example_sentence,
      languageId: language_id,
      createdByUserId: createdByUserId, // Link to the authenticated user
    }).returning();

    res.status(201).json({
      message: 'Vocabulary entry created successfully!',
      vocabEntry: newEntry[0],
    });
    return;

  } catch (error) {
    if (error instanceof ZodError) {
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return;
    }
    console.error('Error creating vocabulary entry:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Get All Vocab Entries (Can be filtered by language_id or user_id) ---
export const getVocabEntries = async (req: Request, res: Response) => {
  try {
    const { language_id, user_id } = req.query; // Optional query parameters for filtering

    let query = db.query.vocabEntries.findMany({
      with: {
        language: true, // Eager load language details
        createdBy: true, // Eager load user who created it
      },
    });

    // Apply filters if provided
    if (language_id) {
      query = db.query.vocabEntries.findMany({
        where: eq(vocabEntries.languageId, language_id as string),
        with: { language: true, createdBy: true },
      });
    }
    if (user_id) {
       query = db.query.vocabEntries.findMany({
        where: eq(vocabEntries.createdByUserId, user_id as string),
        with: { language: true, createdBy: true },
      });
    }
    // Note: If both language_id and user_id are present, you'd need more complex  logic.
    // For simplicity, this example prioritizes user_id if both are present.
    // Consider adding  for multiple filters.

    const allEntries = await query;
    res.json(allEntries);
    return;
  } catch (error) {
    console.error('Error fetching vocabulary entries:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Get Vocab Entry by ID ---
export const getVocabEntryById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params; // Vocab entry ID from URL parameter

    const entry = await db.query.vocabEntries.findFirst({
      where: eq(vocabEntries.id, id),
      with: {
        language: true,
        createdBy: true,
      },
    });

    if (!entry) {
      res.status(404).json({ message: 'Vocabulary entry not found.' });
      return;
    }

    res.json(entry);
    return;
  } catch (error) {
    console.error('Error fetching vocabulary entry by ID:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Update Vocab Entry ---
export const updateVocabEntry = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const createdByUserId = req.userId; // Authenticated user ID
    const userRole = req.role; // Authenticated user role

    if (!createdByUserId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    const updateData: UpdateVocabEntryInput = req.cleanBody;

    // Check if the entry exists and if the current user is the creator OR an admin
    const existingEntry = await db.query.vocabEntries.findFirst({
      where: eq(vocabEntries.id, id),
    });

    if (!existingEntry) {
      res.status(404).json({ message: 'Vocabulary entry not found.' });
      return;
    }

    // Authorization check: Only the creator or an admin can update
    if (existingEntry.createdByUserId !== createdByUserId && userRole !== 'admin') {
      res.status(403).json({ message: 'Forbidden: You do not have permission to update this entry.' });
      return;
    }

    let updatedFields: { [key: string]: any } = { updatedAt: new Date() };

    if (updateData.original_word !== undefined) updatedFields.originalWord = updateData.original_word;
    if (updateData.meaning !== undefined) updatedFields.meaning = updateData.meaning;
    if (updateData.description !== undefined) updatedFields.description = updateData.description;
    if (updateData.example_sentence !== undefined) updatedFields.exampleSentence = updateData.example_sentence;
    if (updateData.language_id !== undefined) {
      // Optional: Verify if the new language_id exists
      const languageExists = await db.query.languages.findFirst({
        where: eq(languages.id, updateData.language_id),
      });
      if (!languageExists) {
        res.status(400).json({ message: 'Invalid language_id provided for update.' });
        return;
      }
      updatedFields.languageId = updateData.language_id;
    }

    const updatedEntries = await db.update(vocabEntries)
      .set(updatedFields)
      .where(eq(vocabEntries.id, id))
      .returning();

    if (updatedEntries.length === 0) {
      res.status(404).json({ message: 'Vocabulary entry not found or no changes applied.' });
      return;
    }

    res.json({
      message: 'Vocabulary entry updated successfully!',
      vocabEntry: updatedEntries[0],
    });
    return;

  } catch (error) {
    if (error instanceof ZodError) {
      res.status(400).json({ message: 'Validation error', errors: error.errors });
      return;
    }
    console.error('Error updating vocabulary entry:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};

// --- Delete Vocab Entry ---
export const deleteVocabEntry = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const createdByUserId = req.userId; // Authenticated user ID
    const userRole = req.role; // Authenticated user role

    if (!createdByUserId) {
      res.status(401).json({ message: 'Unauthorized: User ID missing.' });
      return;
    }

    const existingEntry = await db.query.vocabEntries.findFirst({
      where: eq(vocabEntries.id, id),
    });

    if (!existingEntry) {
      res.status(404).json({ message: 'Vocabulary entry not found.' });
      return;
    }

    // Authorization check: Only the creator or an admin can delete
    if (existingEntry.createdByUserId !== createdByUserId && userRole !== 'admin') {
      res.status(403).json({ message: 'Forbidden: You do not have permission to delete this entry.' });
      return;
    }

    const deletedEntries = await db.delete(vocabEntries)
      .where(eq(vocabEntries.id, id))
      .returning();

    if (deletedEntries.length === 0) {
      res.status(404).json({ message: 'Vocabulary entry not found or could not be deleted.' });
      return;
    }

    res.status(204).send(); // 204 No Content for successful deletion
    return;

  } catch (error) {
    console.error('Error deleting vocabulary entry:', error);
    res.status(500).json({ message: 'Internal server error' });
    return;
  }
};
