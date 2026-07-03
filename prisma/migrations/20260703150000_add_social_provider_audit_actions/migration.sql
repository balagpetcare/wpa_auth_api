DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'AuditAction' AND e.enumlabel = 'SOCIAL_PROVIDER_CREATED') THEN
    ALTER TYPE "AuditAction" ADD VALUE 'SOCIAL_PROVIDER_CREATED';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'AuditAction' AND e.enumlabel = 'SOCIAL_PROVIDER_UPDATED') THEN
    ALTER TYPE "AuditAction" ADD VALUE 'SOCIAL_PROVIDER_UPDATED';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'AuditAction' AND e.enumlabel = 'SOCIAL_PROVIDER_STATUS_CHANGED') THEN
    ALTER TYPE "AuditAction" ADD VALUE 'SOCIAL_PROVIDER_STATUS_CHANGED';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'AuditAction' AND e.enumlabel = 'SOCIAL_PROVIDER_DISABLED') THEN
    ALTER TYPE "AuditAction" ADD VALUE 'SOCIAL_PROVIDER_DISABLED';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'AuditAction' AND e.enumlabel = 'SOCIAL_PROVIDER_DELETED') THEN
    ALTER TYPE "AuditAction" ADD VALUE 'SOCIAL_PROVIDER_DELETED';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'AuditAction' AND e.enumlabel = 'SOCIAL_PROVIDER_TESTED') THEN
    ALTER TYPE "AuditAction" ADD VALUE 'SOCIAL_PROVIDER_TESTED';
  END IF;
END
$$;
