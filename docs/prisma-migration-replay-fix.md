# Prisma migration replay fix

## Root cause

`prisma migrate dev` failed during shadow database replay because the migration history never created the email tables before a later migration tried to alter them.

The failing migration was:

- `prisma/migrations/20260701181326_add_email_production_features/migration.sql`

The failing SQL was:

```sql
ALTER TABLE "email_templates" ADD COLUMN "locale" TEXT NOT NULL DEFAULT 'en'
```

Shadow replay reached that statement while `email_templates` did not exist yet, so PostgreSQL raised `42P01`:

- `ERROR: relation "email_templates" does not exist`

## Why this happened

The current Prisma schema already contains the email models, but the migration chain assumed those tables had been created earlier outside of migrations, or that the database had been manually populated / pushed.

That is not replayable from scratch, which is why shadow database migration application failed.

## Files changed

- [`prisma/migrations/20260701181326_add_email_production_features/migration.sql`](../prisma/migrations/20260701181326_add_email_production_features/migration.sql)

## Fix applied

I made the failing migration self-contained and replayable by adding idempotent `CREATE TABLE IF NOT EXISTS` statements for the missing email tables before the later `ALTER TABLE` statements run:

- `email_templates`
- `email_template_versions`
- `email_template_audit_logs`
- `email_branding_settings`
- `client_brandings`
- `email_send_logs`
- `email_queues`

I also kept the later additive `ALTER TABLE`, index, and foreign key steps so the migration still converges to the current Prisma schema.

## Why this is safe

- The changes are additive only.
- Existing tables are not dropped.
- Existing data is not deleted.
- The migration uses `IF NOT EXISTS` and guarded `DO $$ BEGIN ... EXCEPTION ... END $$;` blocks so it can replay in a shadow database and tolerate already-applied structures in development.

## Verification

Executed verification commands:

1. `npx prisma validate`
2. `npx prisma migrate dev`
3. `npm run check`
4. `npm run build`

Results:

- `npx prisma validate` passed.
- `npm run check` passed.
- `npm run build` passed.
- `npx prisma migrate dev` no longer fails on the original `email_templates does not exist` shadow-replay error, but this local database still reports migration-history divergence because the development database already contains applied migrations that are absent from this checkout.

## Operator follow-up

- If you need to run `npx prisma migrate dev` against this exact local database, restore the missing historical migrations exactly as they existed when the database was created, or use a clean development database. I did not use `migrate resolve` or any destructive reset.
- Run `npm run prisma:seed` only if you need seed data in the local database; the migration fix itself does not require reseeding.
