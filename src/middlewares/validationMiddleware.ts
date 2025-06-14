// src/middlewares/validationMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import _ from 'lodash';
import { z, ZodError } from 'zod';

export function validateData(schema: z.ZodObject<any, any>) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body);
      req.cleanBody = _.pick(req.body, Object.keys(schema.shape));
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errorMessages = error.errors.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));
        // JANGAN gunakan 'return res.status(...)' jika tidak ada 'void' yang eksplisit.
        // Cukup panggil res.status(...).json(...)
        res.status(400).json({
          message: 'Validation error',
          errors: errorMessages
        });
        // PENTING: Karena ini adalah response terakhir, tidak perlu panggil next()
        // dan tidak perlu ada 'return' eksplisit yang mengembalikan nilai.
      } else {
        console.error('Unexpected error in validation middleware:', error);
        res.status(500).json({ message: 'Internal Server Error' });
        // Sama, tidak perlu 'return' yang mengembalikan nilai.
      }
    }
  };
}