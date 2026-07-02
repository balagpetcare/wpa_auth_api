# Database Setup — WPA Auth API

## Overview

The WPA Auth API uses a dedicated PostgreSQL database running inside the shared
`wpa-postgres` Docker container managed by `D:\wpa\docker-infra\docker-compose.yml`.

**Do not use a local Windows PostgreSQL service.** All connections go through Docker.

## Connection Details

| Property        | Value                                  |
|-----------------|----------------------------------------|
| Host            | `127.0.0.1`                            |
| Port            | `5433` (Docker maps 5433 → container 5432) |
| Database        | `wpa_auth_db`                          |
| Shadow DB       | `wpa_auth_shadow_db` (Prisma Migrate)  |
| User            | `wpa_auth_user`                        |
| Password        | see `.env`                             |

## Environment Variables (`.env`)

```
DATABASE_URL=postgresql://wpa_auth_user:wpa_auth_password_123@127.0.0.1:5433/wpa_auth_db
SHADOW_DATABASE_URL=postgresql://wpa_auth_user:wpa_auth_password_123@127.0.0.1:5433/wpa_auth_shadow_db
```

`SHADOW_DATABASE_URL` is used exclusively by `prisma migrate dev` to calculate schema diffs safely
without touching production data.

## Starting the Database

```bash
cd D:\wpa\docker-infra
docker compose up -d wpa-postgres
```

The container mounts `./init/01-create-databases.sql` as an init script.  
This script creates `wpa_auth_user`, `wpa_auth_db`, and `wpa_auth_shadow_db` automatically
on first container creation.

> **Note:** Init scripts only run once, when the volume is first created.
> If the container already exists, the databases are already present and no action is needed.

## Prisma Workflow

```bash
# Generate Prisma Client after schema changes
npx prisma generate

# Create and apply a migration
npx prisma migrate dev --name <migration_name>

# Open Prisma Studio (GUI)
npx prisma studio

# Seed the database
npx prisma db seed
```

## Manual DB Access (if needed)

```bash
# Connect via docker exec
docker exec -it wpa-postgres psql -U wpa_auth_user -d wpa_auth_db

# Or from host using psql
psql -h 127.0.0.1 -p 5433 -U wpa_auth_user -d wpa_auth_db
```

## If the Container Is Recreated

Since the init SQL is idempotent via the Docker init mechanism, databases and users will be
re-created automatically on the next `docker compose up`. No manual SQL needed.

If you need to manually re-provision (e.g. after a volume wipe):

```sql
CREATE USER wpa_auth_user WITH PASSWORD 'wpa_auth_password_123';
ALTER USER wpa_auth_user CREATEDB;
CREATE DATABASE wpa_auth_db OWNER wpa_auth_user;
CREATE DATABASE wpa_auth_shadow_db OWNER wpa_auth_user;
GRANT ALL PRIVILEGES ON DATABASE wpa_auth_db TO wpa_auth_user;
GRANT ALL PRIVILEGES ON DATABASE wpa_auth_shadow_db TO wpa_auth_user;
```

Run via: `docker exec -it wpa-postgres psql -U wpa_root -d postgres`
