import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { z } from 'zod';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from .env
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(5010),
  HOST: z.string().default('0.0.0.0'),
  API_PREFIX: z.string().default('/api/v1'),
  APP_URL: z.string().url().default('http://localhost:5010'),
  DATABASE_URL: z.string(),
  JWT_ACCESS_SECRET: z.string().min(8),
  JWT_REFRESH_SECRET: z.string().min(8),
  ACCESS_TOKEN_TTL: z.string().default('15m'),
  REFRESH_TOKEN_TTL: z.string().default('30d'),
  ACCESS_TOKEN_AUDIENCE: z.string().default('bpa-mobile'),
  // Additive: extra JWT audiences this server will accept at verification
  // time, beyond ACCESS_TOKEN_AUDIENCE (comma-separated, e.g. "furtail-mobile").
  // Per-client tokens are still SIGNED with that client's own
  // AuthClient.audience (see tokens.ts/signAccessToken); this just widens
  // what verifyAccessToken/verifyRefreshToken will accept so a second
  // first-party app (Furtail) can be onboarded without breaking existing
  // BPA tokens, which keep using ACCESS_TOKEN_AUDIENCE unchanged.
  ADDITIONAL_JWT_AUDIENCES: z.string().default(''),
  ADMIN_PANEL_ORIGIN: z.string().url().default('http://localhost:5012'),
  PUBLIC_WEBSITE_ORIGIN: z.string().url().default('http://localhost:5011'),
  // Additive per-client routing for password-reset / email-verification links.
  // The forgot-password + email-verification emails historically hardcoded
  // `${ADMIN_PANEL_ORIGIN}/auth/user/...`, which is correct for the admin
  // panel but wrong for mobile app users (Furtail/BPA) — they need a deep
  // link into their own app. This is a JSON map of clientId -> a base URL (or
  // custom-scheme deep link) that the reset/verify token is appended to as
  // `?token=...`. When a forgot-password/verify request carries a known
  // clientId present in this map, its URL wins; otherwise the ADMIN_PANEL_ORIGIN
  // default is used unchanged (so the admin panel's own reset flow never breaks).
  // Example:
  //   PASSWORD_RESET_URL_BY_CLIENT={"furtail-mobile":"furtail://reset-password","bpa-mobile":"bpa://reset-password"}
  //   EMAIL_VERIFICATION_URL_BY_CLIENT={"furtail-mobile":"furtail://verify-email"}
  PASSWORD_RESET_URL_BY_CLIENT: z.string().default(''),
  EMAIL_VERIFICATION_URL_BY_CLIENT: z.string().default(''),
  ALLOWED_PUBLIC_ORIGINS: z.string().default('http://localhost:5011,http://localhost:5012'),
  // OAuth / OIDC
  OAUTH_ISSUER: z.string().default('http://localhost:5010'),
  // Optional RSA keys for JWKS (PEM, base64-encoded in env). Falls back to HS256 if absent.
  JWT_RSA_PRIVATE_KEY: z.string().optional(),
  JWT_RSA_PUBLIC_KEY: z.string().optional(),
  JWT_RSA_PUBLIC_KEYS_JSON: z.string().optional(),
  // kid advertised in the JWKS response and (once RS256 signing is wired up)
  // embedded in the JWT header — lets relying parties pick the right key
  // during rotation. See getJwks() in oauth.service.ts.
  JWT_KEY_ID: z.string().default('wpa-key-1'),
  AUTH_CODE_TTL_SECONDS: z.coerce.number().default(600), // 10 minutes
  SERVICE_TOKEN_TTL_SECONDS: z.coerce.number().default(3600), // 1 hour
  // Social
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_CALLBACK_URL: z.string().optional(),
  FACEBOOK_CLIENT_ID: z.string().optional(),
  FACEBOOK_CLIENT_SECRET: z.string().optional(),
  FACEBOOK_CALLBACK_URL: z.string().optional(),
  APPLE_CLIENT_ID: z.string().optional(),
  APPLE_TEAM_ID: z.string().optional(),
  APPLE_KEY_ID: z.string().optional(),
  APPLE_PRIVATE_KEY: z.string().optional(),
  APPLE_CALLBACK_URL: z.string().optional(),
  TWITTER_CLIENT_ID: z.string().optional(),
  TWITTER_CLIENT_SECRET: z.string().optional(),
  TWITTER_CALLBACK_URL: z.string().optional(),
  INSTAGRAM_CLIENT_ID: z.string().optional(),
  INSTAGRAM_CLIENT_SECRET: z.string().optional(),
  INSTAGRAM_CALLBACK_URL: z.string().optional(),
  // Furtail centralized-auth identity providers (see
  // src/modules/auth/identity-providers). Each provider is independently
  // togglable: it is only usable when its required env vars are present.
  // A request against a provider missing config returns PROVIDER_DISABLED,
  // never a silent no-op or fake success.
  GOOGLE_LOGIN_AUDIENCE: z.string().optional(), // Google OAuth client ID(s), comma-separated (aud allow-list for ID tokens)
  FACEBOOK_APP_ID: z.string().optional(),
  FACEBOOK_APP_SECRET: z.string().optional(), // used server-side only, to call the debug_token endpoint; never sent to any client
  APPLE_LOGIN_AUDIENCE: z.string().optional(), // Apple Services ID / app bundle id(s), comma-separated
  MICROSOFT_TENANT_ID: z.string().optional().default('common'), // 'common', 'organizations', 'consumers', or a specific tenant GUID
  MICROSOFT_CLIENT_ID: z.string().optional(),
  // OTP (email/phone/whatsapp passwordless login) — reuses the existing
  // CommunicationProvider/antiAbuse.ts infrastructure, not a parallel system.
  OTP_LOGIN_CODE_LENGTH: z.coerce.number().int().min(4).max(10).default(6),
  OTP_LOGIN_EXPIRY_MINUTES: z.coerce.number().int().positive().default(10),
  OTP_LOGIN_MAX_VERIFY_ATTEMPTS: z.coerce.number().int().positive().default(5),
  OTP_LOGIN_RESEND_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(60),
  WHATSAPP_OTP_ENABLED: z.coerce.boolean().default(false),
  // Set to 'true' or a hop count (e.g. '1') when running behind Nginx/load balancer
  // so Express reads X-Forwarded-For and sets req.ip correctly.
  TRUST_PROXY: z.string().optional(),
  REDIS_URL: z.string().optional(),
  CAPTCHA_PROVIDER: z.enum(['none', 'turnstile', 'recaptcha']).default('none'),
  CAPTCHA_SECRET: z.string().optional(),
  CAPTCHA_REQUIRED_ON_HIGH_RISK: z.coerce.boolean().default(false),
  AUTH_ABUSE_PROTECTION_ENABLED: z.coerce.boolean().default(true),
  AUTH_ABUSE_DEV_RELAXED: z.coerce.boolean().default(true),
  AUTH_LOGIN_FAILED_ATTEMPT_LIMIT: z.coerce.number().int().positive().default(5),
  AUTH_LOGIN_BLOCK_MINUTES: z.coerce.number().int().positive().default(15),
  AUTH_LOGIN_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(10),
  AUTH_LOGIN_RATE_LIMIT_WINDOW_MINUTES: z.coerce.number().int().positive().default(15),
  AUTH_LOGIN_LOCAL_BLOCK_MINUTES: z.coerce.number().int().positive().default(2),
  COMMUNICATION_RATE_LIMIT_ENABLED: z.coerce.boolean().default(true),
  DELETION_GRACE_PERIOD_HOURS: z.coerce.number().int().positive().default(72),
  DELETION_PROCESSOR_SCAN_SECONDS: z.coerce.number().int().positive().default(30),
  COMMUNICATION_MAX_SMS_PER_PHONE_PER_HOUR: z.coerce.number().int().positive().default(5),
  COMMUNICATION_MAX_SMS_PER_PHONE_PER_DAY: z.coerce.number().int().positive().default(10),
  COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_HOUR: z.coerce.number().int().positive().default(5),
  COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_DAY: z.coerce.number().int().positive().default(10),
  COMMUNICATION_MAX_PROVIDER_TEST_PER_ADMIN_HOUR: z.coerce.number().int().positive().default(10),
  COMMUNICATION_MAX_BULK_RETRY_COUNT: z.coerce.number().int().positive().default(50),
  COMMUNICATION_SYSTEM_SMS_HOURLY_CAP: z.coerce.number().int().positive().default(200),
  COMMUNICATION_SYSTEM_SMS_DAILY_CAP: z.coerce.number().int().positive().default(2000),
  COMMUNICATION_SYSTEM_EMAIL_HOURLY_CAP: z.coerce.number().int().positive().default(1000),
  COMMUNICATION_SYSTEM_EMAIL_DAILY_CAP: z.coerce.number().int().positive().default(10000),
  PRESENCE_TTL_SECONDS: z.coerce.number().int().positive().default(90),
  PRESENCE_HEARTBEAT_MIN_INTERVAL_SECONDS: z.coerce.number().int().positive().default(30),
  CREDENTIAL_ENCRYPTION_KEY: z.string().min(32),
  CREDENTIAL_ENCRYPTION_KEY_VERSION: z.coerce.number().int().positive().default(1),
  CREDENTIAL_ENCRYPTION_KEYS_JSON: z.string().optional(),
  OTP_EXPIRY_MINUTES: z.coerce.number().default(10),
  OTP_APP_NAME: z.string().default('WPA Central Auth'),
  OTP_SUPPORT_EMAIL: z.string().email().default('support@wpa.local'),
  AUDIT_LOG_RETENTION_DAYS: z.coerce.number().int().positive().default(365),
  SECURITY_EVENT_RETENTION_DAYS: z.coerce.number().int().positive().default(365),
  ADMIN_NOTIFICATION_RETENTION_DAYS: z.coerce.number().int().positive().default(180),
  COMMUNICATION_DELIVERY_LOG_RETENTION_DAYS: z.coerce.number().int().positive().default(180),
  COMMUNICATION_PROVIDER_AUDIT_LOG_RETENTION_DAYS: z.coerce.number().int().positive().default(365),
  LOGIN_SESSION_RETENTION_DAYS: z.coerce.number().int().positive().default(180),
  AUTHORIZATION_CODE_RETENTION_DAYS: z.coerce.number().int().positive().default(7),
  REFRESH_TOKEN_RETENTION_DAYS: z.coerce.number().int().positive().default(180),
  RETENTION_PRUNE_BATCH_SIZE: z.coerce.number().int().positive().default(1000),
  COMMUNICATION_RETRY_WORKER_ENABLED: z
    .string()
    .optional()
    .transform((v) => v !== 'false')
    .default('true'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.format());
  process.exit(1);
}

export const config = parsed.data;
