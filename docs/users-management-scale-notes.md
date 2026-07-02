# Users Management - Scaling Notes

This document outlines the architectural decisions and database optimizations made to ensure the Users Management module scales safely to millions (or even 1B+) of users.

## Server-Side Filtering
- **Why it's required:** Client-side filtering is only viable for datasets up to a few thousand rows. At massive scale, loading millions of user objects into memory is impossible and would crash the Node.js process. All filtering is pushed down to the database using SQL `WHERE` clauses.

## Cursor Pagination
- **Why cursor is preferred over offset:** Offset pagination (`OFFSET X LIMIT Y`) forces the database to scan and discard `X` rows before returning the `Y` rows. At page 10,000, this becomes extremely slow.
- **Keyset / Cursor Pagination:** Instead of saying "skip 1,000,000 rows", we use a cursor indicating "fetch the next 50 rows where `id > last_seen_id`". This is an O(1) index lookup and maintains consistent performance regardless of page depth.

## PostgreSQL Indexes
The following standard `btree` indexes have been deployed for efficient querying:
- `users(status)`
- `users(createdAt)`
- `users(lastLoginAt)`
- `users(email)`
- `users(username)`
- `users(phone)`

### Compound Indexes for Cursor Sorting
To support rapid keyset pagination coupled with sorting, compound indexes tie the sort parameter to the cursor tie-breaker:
- `users(createdAt, id)`
- `users(lastLoginAt, id)`
- `users(status, createdAt, id)`

## Text Search Optimization
- **Current state:** The system utilizes safe `ILIKE` (`contains` with `mode: 'insensitive'` in Prisma) on specific indexed string columns. 
- **Future recommendation (`pg_trgm`):** As the dataset crosses the 1-10M mark, standard `btree` indexes lose effectiveness on `LIKE '%search%'` queries. It is highly recommended to enable the PostgreSQL `pg_trgm` extension and create Generalized Inverted Indexes (GIN) on the searchable columns (`email`, `username`, `displayName`).
  - Example: `CREATE INDEX users_email_trgm_idx ON users USING GIN (email gin_trgm_ops);`

## Massive Scale Evolution (100M+ Users)
- **Search Infrastructure:** If global fuzzy search across multiple fields becomes a bottleneck for PostgreSQL even with trigrams, migrate the search workload to a dedicated search engine like **Elasticsearch**, **OpenSearch**, or **Meilisearch**.
- **Data Exports:** Exporting users at this scale must never be a direct HTTP response. It must be implemented as a background job (e.g., via BullMQ/Redis) that streams the dataset to an S3 bucket and emails the admin a secure download link.
