// src/routes/index.ts
import { Router } from 'express';
import userRoutes from './users'; // User authentication routes
import vocabEntriesRoutes from './vocabEntries'; // NEW: Vocab Entries routes

// Import other route modules here if you have them:
// import languageRoutes from './languages';
// import categoryRoutes from './categories';
// import userVocabProgressRoutes from './userVocabProgress'; // If you decide to add dedicated routes for this

const router = Router();

// Mount user authentication routes under /auth
router.use('/auth', userRoutes); // All user/auth routes will be prefixed with /api/auth

// Mount vocab entries routes under /vocab-entries
router.use('/vocab-entries', vocabEntriesRoutes); // All vocab entries routes will be prefixed with /api/vocab-entries

// Mount other route modules here:
// router.use('/languages', languageRoutes);
// router.use('/categories', categoryRoutes);
// router.use('/user-vocab-progress', userVocabProgressRoutes);

export default router;
