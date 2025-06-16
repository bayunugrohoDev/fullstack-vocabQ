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
