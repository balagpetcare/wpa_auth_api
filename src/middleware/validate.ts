import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

export function validateBody(schema: ZodSchema) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const issues = error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
          code: issue.code,
        }));
        res.status(400).json({
          success: false,
          message: issues.length > 0 ? `Validation failed for ${issues.map((issue) => issue.field).join(', ')}.` : 'Validation failed.',
          code: 'VALIDATION_ERROR',
          issues,
          errors: issues,
        });
        return;
      }
      next(error);
    }
  };
}
