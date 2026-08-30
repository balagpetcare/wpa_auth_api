-- WPA true global logout contract: per-client post-logout redirect allowlist.
-- Additive and defaulted so every existing client row is unaffected.
ALTER TABLE "auth_clients"
  ADD COLUMN "post_logout_redirect_uris" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
