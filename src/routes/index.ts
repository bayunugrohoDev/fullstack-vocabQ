// src/routes/index.ts
import { Router } from 'express';
import userRoutes from './users'; // Import the user authentication routes

// Import other route modules here if you have them:
// import languageRoutes from './languages';
// import categoryRoutes from './categories';
// import vocabularyRoutes from './vocabularies';

const router = Router();

// Mount user authentication routes under /auth
router.use('/auth', userRoutes); // All user/auth routes will be prefixed with /api/auth

// Mount other route modules here:
// router.use('/languages', languageRoutes);
// router.use('/categories', categoryRoutes);
// router.use('/vocabularies', vocabularyRoutes);

export default router;
