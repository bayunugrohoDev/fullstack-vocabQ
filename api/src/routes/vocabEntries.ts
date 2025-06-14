// src/routes/vocabEntries.ts
import { Router } from 'express';
import {
  createVocabEntry,
  getVocabEntries,
  getVocabEntryById,
  updateVocabEntry,
  deleteVocabEntry,
} from '../controllers/vocabEntries';
import { validateData } from '../middlewares/validationMiddleware'; // Zod validation middleware
import { verifyToken, authorizeRoles } from '../middlewares/authMiddleware'; // Auth middleware, include authorizeRoles if needed
import { createVocabEntrySchema, updateVocabEntrySchema } from '../validation/vocabEntryValidation'; // Zod schemas

const router = Router();

// --- Protected Routes (Authentication Required) ---

// Create a new vocabulary entry: POST /api/vocab-entries
router.post('/', verifyToken, validateData(createVocabEntrySchema), createVocabEntry);

// Get all vocabulary entries (can be filtered): GET /api/vocab-entries
// Note: You might want to protect this or add pagination later
router.get('/', verifyToken, getVocabEntries);

// Get a specific vocabulary entry by ID: GET /api/vocab-entries/:id
router.get('/:id', verifyToken, getVocabEntryById);

// Update a vocabulary entry by ID: PUT /api/vocab-entries/:id
// Only creator or admin can update
router.put('/:id', verifyToken, validateData(updateVocabEntrySchema), updateVocabEntry);

// Delete a vocabulary entry by ID: DELETE /api/vocab-entries/:id
// Only creator or admin can delete
router.delete('/:id', verifyToken, deleteVocabEntry);

export default router;
