import { Request, Response, NextFunction } from 'express';
import { getRedisClient } from '../lib/redis.js';

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

interface Window {
  count: number;
  resetAt: number;
}

// In-memory store used only in development/test when Redis is absent.
const memoryStore = new Map<string, Window>();

export function rateLimit(opts: {
  name: string;          // unique limiter name — included in the Redis key so each endpoint has its own counter
  windowMs: number;
  max: number;
  keyFn?: (req: Request) => string;
}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const identifier = opts.keyFn ? opts.keyFn(req) : (req.ip ?? 'unknown');
    // Key format: rate-limit:<limiter-name>:<client-identifier>
    // Including the limiter name ensures each endpoint has an independent counter per IP.
    const key = `rate-limit:${opts.name}:${identifier}`;
    const windowSeconds = Math.ceil(opts.windowMs / 1000);
    const redisClient = getRedisClient();

    if (redisClient) {
      try {
        const current = await redisClient.incr(key);
        if (current === 1) {
          await redisClient.expire(key, windowSeconds);
        }
        if (current > opts.max) {
          res.status(429).json({ success: false, message: 'Too many requests, please try again later.', code: 'RATE_LIMITED' });
          return;
        }
        return next();
      } catch (err) {
        // In production, Redis failure means shared rate limiting is broken.
        // Fail with 503 rather than silently bypass shared protection.
        if (IS_PRODUCTION) {
          console.error('Redis rate limit unavailable in production:', (err as Error).message);
          res.status(503).json({ success: false, message: 'Service temporarily unavailable. Please try again shortly.', code: 'SERVICE_UNAVAILABLE' });
          return;
        }
        // In development/test, fall through to in-memory.
        console.error('Redis rate limit error, falling back to memory store', err);
      }
    }

    if (IS_PRODUCTION) {
      // Should never reach here in production — createRedisClient() exits if REDIS_URL is absent.
      // Defensive guard in case Redis client was never initialised at all.
      res.status(503).json({ success: false, message: 'Rate limiting unavailable.', code: 'SERVICE_UNAVAILABLE' });
      return;
    }

    // Development/test in-memory fallback.
    const now = Date.now();
    let w = memoryStore.get(key);

    if (!w || now > w.resetAt) {
      w = { count: 1, resetAt: now + opts.windowMs };
      memoryStore.set(key, w);
      return next();
    }

    w.count++;
    if (w.count > opts.max) {
      res.status(429).json({ success: false, message: 'Too many requests, please try again later.', code: 'RATE_LIMITED' });
      return;
    }
    next();
  };
}

const loginWindow = Number(process.env.RATE_LIMIT_LOGIN_WINDOW_MS) || 15 * 60 * 1000;
const loginMax = Number(process.env.RATE_LIMIT_LOGIN_MAX) || 10;
export const loginRateLimit = rateLimit({ name: 'login', windowMs: loginWindow, max: loginMax });

const registerWindow = Number(process.env.RATE_LIMIT_REGISTER_WINDOW_MS) || 60 * 60 * 1000;
const registerMax = Number(process.env.RATE_LIMIT_REGISTER_MAX) || 5;
export const registerRateLimit = rateLimit({ name: 'register', windowMs: registerWindow, max: registerMax });

export const forgotPasswordRateLimit = rateLimit({ name: 'forgot-password', windowMs: 60 * 60 * 1000, max: 5 });
export const refreshRateLimit = rateLimit({ name: 'refresh', windowMs: 15 * 60 * 1000, max: 30 });
export const resetPasswordRateLimit = rateLimit({ name: 'reset-password', windowMs: 15 * 60 * 1000, max: 5 });
export const oauthAuthorizeRateLimit = rateLimit({ name: 'oauth-authorize', windowMs: 15 * 60 * 1000, max: 20 });
export const oauthTokenRateLimit = rateLimit({ name: 'oauth-token', windowMs: 15 * 60 * 1000, max: 50 });
export const oauthIntrospectRateLimit = rateLimit({ name: 'oauth-introspect', windowMs: 15 * 60 * 1000, max: 100 });
export const oauthRevokeRateLimit = rateLimit({ name: 'oauth-revoke', windowMs: 15 * 60 * 1000, max: 50 });
export const socialStartRateLimit = rateLimit({ name: 'social-start', windowMs: 15 * 60 * 1000, max: 30 });
export const socialCallbackRateLimit = rateLimit({ name: 'social-callback', windowMs: 15 * 60 * 1000, max: 30 });
export const socialMobileRateLimit = rateLimit({ name: 'social-mobile', windowMs: 15 * 60 * 1000, max: 20 });

// Email management rate limits
export const emailBrandingRateLimit = rateLimit({ name: 'email-branding', windowMs: 5 * 60 * 1000, max: 10 }); // 10 updates per 5 minutes
export const sendTestEmailRateLimit = rateLimit({ name: 'send-test-email', windowMs: 60 * 1000, max: 5 }); // 5 test emails per minute
