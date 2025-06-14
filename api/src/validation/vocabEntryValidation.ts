// src/validation/vocabEntryValidation.ts
import { z } from 'zod';

// Schema untuk membuat entri vocabulary baru
export const createVocabEntrySchema = z.object({
  original_word: z.string().min(1, 'Original word is required').trim(),
  meaning: z.string().min(1, 'Meaning is required').trim(),
  description: z.string().trim().optional().nullable(), // Opsional
  example_sentence: z.string().trim().optional().nullable(), // Opsional
  language_id: z.string().uuid('Invalid language ID format').nonempty('Language ID is required'), // Harus UUID valid
});

// Schema untuk memperbarui entri vocabulary
// Semua field opsional karena ini adalah update parsial
export const updateVocabEntrySchema = z.object({
  original_word: z.string().min(1, 'Original word cannot be empty').trim().optional(),
  meaning: z.string().min(1, 'Meaning cannot be empty').trim().optional(),
  description: z.string().trim().optional().nullable(),
  example_sentence: z.string().trim().optional().nullable(),
  language_id: z.string().uuid('Invalid language ID format').optional(),
}).refine(data => Object.keys(data).length > 0, {
  message: "At least one field must be provided for update (original_word, meaning, description, example_sentence, or language_id)",
  path: ["body"],
});

// Export inferred types for convenience
export type CreateVocabEntryInput = z.infer<typeof createVocabEntrySchema>;
export type UpdateVocabEntryInput = z.infer<typeof updateVocabEntrySchema>;



