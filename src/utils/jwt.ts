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
