# Prisma Seed Email Template Fix

## Root Cause

`prisma/seed.ts` was calling `prisma.emailTemplate.findUnique()` with:

```ts
where: { key: template.key }
```

That stopped working after `EmailTemplate` changed to a compound unique constraint on:

```prisma
@@unique([key, locale, clientId])
```

Prisma now requires the compound unique input, not a single `key` lookup.

## File Changed

- `prisma/seed.ts`

## Old Invalid Lookup

```ts
await prisma.emailTemplate.findUnique({
  where: { key: template.key },
})
```

## New Safe Lookup

The seed now:

- normalizes `locale` to `template.locale ?? 'en'`
- normalizes `clientId` to `template.clientId ?? null`
- uses `findFirst()` with `key`, `locale`, and `clientId`
- updates by `id` when the template already exists
- creates a new row when it does not exist

It also preserves admin customization rules:

- if `updatedByAdminId` is set and `FORCE_RESEED` is not `true`, the template is skipped
- if `FORCE_RESEED=true`, the existing row is updated

## Verification Results

- `npx prisma validate` passed
- `npm run check` passed
- `npm run build` passed
- `npm run prisma:seed` passed

## Seed Status

`npm run prisma:seed` now completes successfully.
