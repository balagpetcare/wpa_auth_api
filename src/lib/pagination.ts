import { Request } from 'express';
import { AppError } from './errors.js';

export type CursorPaginationInput = {
  limit: number;
  cursor?: string;
  page?: number;
};

export type CursorPaginationResult<T> = {
  items: T[];
  nextCursor: string | null;
  hasNextPage: boolean;
  limit: number;
};

export interface PaginationParams {
  page: number;
  limit: number;
  skip: number;
}

export function parsePagination(req: Request, defaultLimit = 20): PaginationParams {
  const page = Math.max(1, parseInt(req.query['page'] as string) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query['limit'] as string) || defaultLimit));
  return { page, limit, skip: (page - 1) * limit };
}

export function paginatedResponse<T>(data: T[], total: number, { page, limit }: PaginationParams) {
  return {
    data,
    meta: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    },
  };
}

export function encodeCursor(input: { createdAt: Date; id: string }) {
  return Buffer.from(JSON.stringify({ createdAt: input.createdAt.toISOString(), id: input.id }), 'utf8').toString('base64url');
}

export function decodeCursor(cursor: string): { createdAt: Date; id: string } {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as { createdAt?: string; id?: string };
    if (!parsed?.createdAt || !parsed?.id) {
      throw new Error('Invalid cursor');
    }
    const createdAt = new Date(parsed.createdAt);
    if (Number.isNaN(createdAt.getTime())) {
      throw new Error('Invalid cursor date');
    }
    return { createdAt, id: parsed.id };
  } catch {
    throw new AppError('Invalid cursor.', 'VALIDATION_ERROR', 400);
  }
}

export function parseCursorLimit(limit?: number, defaultLimit = 50) {
  return Math.min(100, Math.max(1, limit || defaultLimit));
}
