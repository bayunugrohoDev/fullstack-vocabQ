#!/bin/bash

echo "--- Starting complete rebuild of user authentication API components ---"

# --- 1. Clean (remove) existing relevant files to ensure a fresh start ---
echo "Cleaning up existing files..."
rm -f src/types/express.d.ts
rm -f src/validation/userValidation.ts
rm -f src/utils/jwt.ts
rm -f src/middlewares/validationMiddleware.ts
rm -f src/middlewares/authMiddleware.ts
rm -f src/controllers/users.ts
rm -f src/routes/users.ts
# We won't remove src/routes/index.ts entirely, but its content will be overwritten
echo "Cleanup complete."

# --- 2. Create essential directories if they don't exist ---
echo "Creating/Ensuring directories exist..."
mkdir -p src/types
mkdir -p src/middlewares
mkdir -p src/utils
mkdir -p src/validation
mkdir -p src/controllers
mkdir -p src/routes
echo "Directories ensured."

# --- 3. src/types/express.d.ts (CRUCIAL FOR TYPE EXTENSION) ---
echo "Creating src/types/express.d.ts..."
cat <<EOL > src/types/express.d.ts
// src/types/express.d.ts

// This makes the file a module and avoids the TypeScript error "all files in a project are modules"
export {};

declare global {
  namespace Express {
    // Extend the Express Request interface to add custom properties
    export interface Request {
      // Property added by the 'validateData' middleware
      // 'any' is used for flexibility, but could be refined with Zod.infer<typeof aSpecificSchema>
      cleanBody?: any;

      // Properties added by the 'verifyToken' middleware
      // userId is typically a string (UUID) from the database
      userId?: string;
      // role is a string, made optional here as it's added dynamically by middleware
      role?: string;

      // Include rawBody if you expect to handle raw request bodies (e.g., for webhooks)
      rawBody?: Buffer;
    }
  }
}
EOL
echo "Created src/types/express.d.ts"

# --- 4. src/validation/userValidation.ts (Zod Schemas for input validation) ---
echo "Creating src/validation/userValidation.ts..."
cat <<EOL > src/validation/userValidation.ts
// src/validation/userValidation.ts
import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().min(1, 'Name is required').trim(),
  email: z.string().email('Invalid email address').toLowerCase().trim(),
  password: z.string().min(6, 'Password must be at least 6 characters long'),
  // current_language_id can be optional and nullable if user doesn't pick one during registration
  current_language_id: z.string().uuid('Invalid language ID format').optional().nullable(),
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email address').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required'), // Password length validation can be more relaxed for login
});

export const updateUserSchema = z.object({
  name: z.string().min(1, 'Name cannot be empty').trim().optional(),
  email: z.string().email('Invalid email address').toLowerCase().trim().optional(),
  password: z.string().min(6, 'Password must be at least 6 characters long').optional(),
  current_language_id: z.string().uuid('Invalid language ID format').optional().nullable(),
}).refine(data => Object.keys(data).length > 0, {
  message: "At least one field (name, email, password, current_language_id) must be provided for update",
  path: ["body"], // Zod error path
});

// Export inferred types for convenience
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
EOL
echo "Created src/validation/userValidation.ts"

# --- 5. src/utils/jwt.ts (JWT token generation and verification utilities) ---
echo "Creating src/utils/jwt.ts..."
cat <<EOL > src/utils/jwt.ts
// src/utils/jwt.ts
import jwt from 'jsonwebtoken';

// IMPORTANT: Get JWT_SECRET from environment variables. Provide a strong default for development.
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_strong_jwt_secret_key_please_change_this_in_production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d'; // Token expiry time

// Define the structure of the JWT payload
interface UserJwtPayload {
  userId: string;
  email: string;
  role?: string; // Role of the user, optional in payload
}

/**
 * Generates a JWT token for a given user payload.
 * @param payload The user data to embed in the token.
 * @returns A signed JWT token string.
 */
export const generateToken = (payload: UserJwtPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

/**
 * Verifies a JWT token and returns its decoded payload.
 * This is a utility function, separate from the Express middleware.
 * @param token The JWT token string.
 * @returns The decoded UserJwtPayload if valid, otherwise null.
 */
export const verifyTokenUtil = (token: string): UserJwtPayload | null => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as UserJwtPayload;
    return decoded;
  } catch (error) {
    console.error('JWT utility verification failed:', error);
    return null;
  }
};
EOL
echo "Created src/utils/jwt.ts"

# --- 6. src/middlewares/validationMiddleware.ts (Middleware for Zod data validation) ---
echo "Creating src/middlewares/validationMiddleware.ts..."
cat <<EOL > src/middlewares/validationMiddleware.ts
// src/middlewares/validationMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import _ from 'lodash'; // Requires lodash: npm install lodash @types/lodash
import { z, ZodError } from 'zod';

/**
 * Middleware to validate request body data against a Zod schema.
 * Stores the validated (and picked) data in req.cleanBody.
 * @param schema The Zod schema to validate against.
 * @returns An Express middleware function.
 */
export function validateData(schema: z.ZodObject<any, any>) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Parse (validate) req.body using the provided schema
      schema.parse(req.body);
      // Pick only the properties defined in the schema to create a 'clean' body
      // This prevents extraneous or malicious properties from being passed
      req.cleanBody = _.pick(req.body, Object.keys(schema.shape));
      next(); // Proceed to the next middleware or route handler
    } catch (error) {
      if (error instanceof ZodError) {
        // Handle Zod validation errors
        const errorMessages = error.errors.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));
        return res.status(400).json({
          message: 'Validation error',
          errors: errorMessages
        });
      } else {
        // Handle any unexpected errors
        console.error('Unexpected error in validation middleware:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
      }
    }
  };
}
EOL
echo "Created src/middlewares/validationMiddleware.ts"

# --- 7. src/middlewares/authMiddleware.ts (Authentication and Authorization Middlewares) ---
echo "Creating src/middlewares/authMiddleware.ts..."
cat <<EOL > src/middlewares/authMiddleware.ts
// src/middlewares/authMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// IMPORTANT: Get JWT_SECRET from environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_strong_jwt_secret_key_please_change_this_in_production';

/**
 * Middleware to verify a JWT token from the Authorization header.
 * Populates req.userId (string) and req.role (string) if token is valid.
 * @returns An Express middleware function.
 */
export function verifyToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.header('Authorization');
  // Extract token from 'Bearer TOKEN' format or direct token
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Ensure decoded payload is an object and contains a string userId
    if (typeof decoded !== 'object' || !decoded || !('userId' in decoded) || typeof decoded.userId !== 'string') {
      return res.status(401).json({ message: 'Invalid token payload or userId type mismatch.' });
    }

    // Assign userId (string) and role (with a default if not present in token) to the Request object
    req.userId = decoded.userId;
    req.role = (decoded as any).role || 'user'; // Assert 'any' to access custom properties, and provide a default role

    next(); // Proceed to the next middleware or route handler
  } catch (e) {
    console.error('JWT verification error:', e);
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

/**
 * Middleware to restrict access to specific roles (e.g., 'seller').
 * Assumes verifyToken middleware has already run and populated req.role.
 * @param allowedRoles An array of roles that are allowed to access the route.
 * @returns An Express middleware function.
 */
export function authorizeRoles(allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    // req.role is expected to be populated by verifyToken
    const userRole = req.role;

    if (!userRole || !allowedRoles.includes(userRole)) {
      return res.status(403).json({ message: 'Forbidden: Insufficient role permissions.' });
    }
    next();
  };
}

// Specific role check examples (optional, can use authorizeRoles directly)
export const verifySeller = authorizeRoles(['seller']);
export const verifyAdmin = authorizeRoles(['admin']);
EOL
echo "Created src/middlewares/authMiddleware.ts"

# --- 8. src/controllers/users.ts (User specific API logic) ---
echo "Creating src/controllers/users.ts..."
cat <<EOL > src/controllers/users.ts
// src/controllers/users.ts
import { Request, Response } from 'express';
import { db } from '../db'; // Your Drizzle DB instance
import { users, languages } from '../db/schema'; // Your Drizzle schemas
import { eq } from 'drizzle-orm'; // Drizzle ORM utility for equality
import bcrypt from 'bcryptjs'; // For password hashing
import { generateToken } from '../utils/jwt'; // Utility to generate JWTs
import { registerSchema, loginSchema, updateUserSchema } from '../validation/userValidation'; // Zod schemas
import { ZodError } from 'zod'; // Zod error type for validation errors

// --- User Registration ---
export const registerUser = async (req: Request, res: Response) => {
  try {
    // req.cleanBody is populated by the validateData middleware
    // We parse it again here for strong type safety within the controller,
    // though the data is already validated by the middleware.
    const userData = registerSchema.parse(req.cleanBody);
    const { name, email, password, current_language_id } = userData;

    // Check if user with this email already exists
    const existingUser = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    if (existingUser) {
      return res.status(409).json({ message: 'Email already registered.' });
    }

    // Hash the user's password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const newUser = await db.insert(users).values({
      name,
      email,
      password: hashedPassword,
      currentLanguageId: current_language_id || null, // Handle nullable language ID
      // If you have a 'role' column in your users table, you might set a default here:
      // role: 'user',
    }).returning(); // Get the inserted user data back

    // Exclude password from the response object for security
    const { password: userPassword, ...userWithoutPassword } = newUser[0];
    
    // Generate a JWT for the new user
    const token = generateToken({
      userId: userWithoutPassword.id,
      email: userWithoutPassword.email,
      // role: userWithoutPassword.role, // Include role if it's in your users table
    });

    res.status(201).json({
      message: 'User registered successfully!',
      user: userWithoutPassword,
      token,
    });

  } catch (error) {
    // Handle Zod validation errors (though validateData middleware should catch most)
    if (error instanceof ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    console.error('Error during user registration:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// --- User Login ---
export const loginUser = async (req: Request, res: Response) => {
  try {
    // req.cleanBody is populated by the validateData middleware
    const { email, password } = loginSchema.parse(req.cleanBody);

    // Find user by email
    const user = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials (email not found).' });
    }

    // Compare provided password with hashed password from DB
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials (password mismatch).' });
    }

    // Exclude password from the response object
    const { password: userPassword, ...userWithoutPassword } = user;
    
    // Generate a JWT for the authenticated user
    const token = generateToken({
      userId: userWithoutPassword.id,
      email: userWithoutPassword.email,
      // role: userWithoutPassword.role, // Include role if it's in your users table
    });

    res.status(200).json({
      message: 'Login successful!',
      token,
      user: userWithoutPassword,
    });

  } catch (error) {
    if (error instanceof ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    console.error('Error during user login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// --- Get Current Authenticated User's Profile ---
export const getCurrentUser = async (req: Request, res: Response) => {
  try {
    // req.userId is populated by the verifyToken middleware
    const userId = req.userId;

    // This check should ideally not be hit if verifyToken middleware runs correctly
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated or ID missing.' });
    }

    // Fetch user details from the database
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        currentLanguage: true, // Eager load related language data
      },
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Exclude password from the response
    const { password: userPassword, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);

  } catch (error) {
    console.error('Error fetching current user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// --- Update Current Authenticated User's Profile ---
export const updateCurrentUser = async (req: Request, res: Response) => {
  try {
    const userId = req.userId;
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated.' });
    }

    // req.cleanBody is populated by validateData middleware
    const updateData = updateUserSchema.parse(req.cleanBody);

    let updatedFields: { [key: string]: any } = { updatedAt: new Date() }; // Always update timestamp

    // Conditionally add fields to update if they are present in the request
    if (updateData.name !== undefined) updatedFields.name = updateData.name;
    if (updateData.email !== undefined) {
        // Check if the new email is already in use by another user
        const existingUserWithEmail = await db.query.users.findFirst({
            where: eq(users.email, updateData.email),
        });
        if (existingUserWithEmail && existingUserWithEmail.id !== userId) {
            return res.status(409).json({ message: 'Email already taken by another user.' });
        }
        updatedFields.email = updateData.email;
    }
    if (updateData.password !== undefined) {
      updatedFields.password = await bcrypt.hash(updateData.password, 10);
    }
    if (updateData.current_language_id !== undefined) {
      updatedFields.currentLanguageId = updateData.current_language_id;
    }

    // Perform the update operation
    const updatedUsers = await db.update(users)
      .set(updatedFields)
      .where(eq(users.id, userId))
      .returning(); // Get the updated user data back

    if (updatedUsers.length === 0) {
      return res.status(404).json({ message: 'User not found or nothing to update.' });
    }

    const { password: userPassword, ...userWithoutPassword } = updatedUsers[0];
    res.json(userWithoutPassword);

  } catch (error) {
    if (error instanceof ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    console.error('Error updating user profile:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// --- Delete Current Authenticated User's Account ---
export const deleteCurrentUser = async (req: Request, res: Response) => {
  try {
    const userId = req.userId;
    if (!userId) {
      return res.status(401).json({ message: 'User not authenticated.' });
    }

    // Perform the delete operation
    const deletedUsers = await db.delete(users)
      .where(eq(users.id, userId))
      .returning(); // Get the deleted user data back (optional)

    if (deletedUsers.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(204).send(); // Send 204 No Content for successful deletion
  } catch (error) {
    console.error('Error deleting user account:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};
EOL
echo "Created src/controllers/users.ts"

# --- 9. src/routes/users.ts (User specific API routes) ---
echo "Creating src/routes/users.ts..."
cat <<EOL > src/routes/users.ts
// src/routes/users.ts
import { Router } from 'express';
import {
  registerUser,
  loginUser,
  getCurrentUser,
  updateCurrentUser,
  deleteCurrentUser
} from '../controllers/users';
import { validateData } from '../middlewares/validationMiddleware'; // Middleware for Zod validation
import { verifyToken } from '../middlewares/authMiddleware';     // Middleware for JWT authentication
import { registerSchema, loginSchema, updateUserSchema } from '../validation/userValidation'; // Zod schemas

const router = Router();

// --- Public Routes (No authentication required) ---
// User registration: POST /api/auth/register
router.post('/register', validateData(registerSchema), registerUser);
// User login: POST /api/auth/login
router.post('/login', validateData(loginSchema), loginUser);

// --- Protected Routes (Authentication required via verifyToken middleware) ---
// Get current authenticated user's profile: GET /api/auth/me
router.get('/me', verifyToken, getCurrentUser);
// Update current authenticated user's profile: PUT /api/auth/me
router.put('/me', verifyToken, validateData(updateUserSchema), updateCurrentUser);
// Delete current authenticated user's account: DELETE /api/auth/me
router.delete('/me', verifyToken, deleteCurrentUser);

export default router;
EOL
echo "Created src/routes/users.ts"

# --- 10. src/routes/index.ts (Main router to mount all sub-routers) ---
echo "Creating src/routes/index.ts (main router)..."
cat <<EOL > src/routes/index.ts
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
EOL
echo "Created src/routes/index.ts"

# --- 11. Reminder/Check for src/app.ts setup ---
echo "---------------------------------------------------------"
echo "IMPORTANT: Please ensure your src/app.ts file is correctly configured."
echo "It should look similar to this to parse JSON and mount your main API routes:"
echo "---"
echo "import express from 'express';"
echo "import routes from './routes';"
echo ""
echo "const app = express();"
echo ""
echo "app.use(express.json()); // Essential for parsing JSON request bodies"
echo "app.use('/api', routes); // Mount your main API routes under /api"
echo ""
echo "app.get('/', (req, res) => {"
echo "  res.send('API is running! Visit /api for endpoints.');"
echo "});"
echo ""
echo "export default app;"
echo "---"
echo "---------------------------------------------------------"

# --- 12. Dependencies Installation Reminder ---
echo "---------------------------------------------------------"
echo "Please install the following npm packages if you haven't already:"
echo "npm install jsonwebtoken bcryptjs zod lodash"
echo "npm install --save-dev @types/jsonwebtoken @types/bcryptjs @types/zod @types/lodash"
echo "---------------------------------------------------------"

# --- 13. Environment Variable Reminder ---
echo "---------------------------------------------------------"
echo "VERY IMPORTANT: Ensure 'JWT_SECRET' is set in your .env.local file."
echo "Example:"
echo "JWT_SECRET=your_super_strong_random_secret_key_for_jwt_prod_only"
echo "You can generate a strong key using: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
echo "---------------------------------------------------------"

echo "--- Complete rebuild of user authentication API components finished ---"
echo "Remember to run 'npm install' and 'npm run dev' to start your server."