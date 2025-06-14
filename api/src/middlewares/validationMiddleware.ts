// src/middlewares/validationMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import _ from 'lodash';
import { z, ZodError } from 'zod';

// Ubah tipe schema menjadi z.ZodSchema
export function validateData(schema: z.ZodSchema<any>) { // <--- KOREKSI PENTING DI SINI
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Menggunakan parse untuk validasi dan untuk mendapatkan data yang sudah divalidasi/diproses Zod
      req.cleanBody = schema.parse(req.body); // <--- KOREKSI PENTING DI SINI
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errorMessages = error.errors.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));
        res.status(400).json({
          message: 'Validation error',
          errors: errorMessages
        });
        return;
      } else {
        console.error('Unexpected error in validation middleware:', error);
        res.status(500).json({ message: 'Internal Server Error' });
        return;
      }
    }
  };
}