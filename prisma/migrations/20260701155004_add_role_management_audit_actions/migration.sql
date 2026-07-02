-- Phase 2 role-permission management API
-- Additive-only, non-destructive enum extension (no data loss, no table changes).
ALTER TYPE "AuditAction" ADD VALUE 'ROLE_CREATED';
ALTER TYPE "AuditAction" ADD VALUE 'ROLE_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'ROLE_DELETED';
