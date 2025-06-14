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
