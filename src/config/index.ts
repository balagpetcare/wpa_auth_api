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
  ADMIN_PANEL_ORIGIN: z.string().url().default('http://localhost:5012'),
  ALLOWED_PUBLIC_ORIGINS: z.string().default('http://localhost:3000,http://localhost:5012'),
  // OAuth / OIDC
  OAUTH_ISSUER: z.string().default('http://localhost:5010'),
  // Optional RSA keys for JWKS (PEM, base64-encoded in env). Falls back to HS256 if absent.
  JWT_RSA_PRIVATE_KEY: z.string().optional(),
  JWT_RSA_PUBLIC_KEY: z.string().optional(),
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
  // Set to 'true' or a hop count (e.g. '1') when running behind Nginx/load balancer
  // so Express reads X-Forwarded-For and sets req.ip correctly.
  TRUST_PROXY: z.string().optional(),
  REDIS_URL: z.string().optional(),
  CREDENTIAL_ENCRYPTION_KEY: z.string().min(32),
  OTP_EXPIRY_MINUTES: z.coerce.number().default(10),
  OTP_APP_NAME: z.string().default('WPA Central Auth'),
  OTP_SUPPORT_EMAIL: z.string().email().default('support@wpa.local'),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.format());
  process.exit(1);
}

export const config = parsed.data;
