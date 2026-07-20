import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config/index.js';
import { logger } from './lib/logger.js';
import { createRedisClient, closeRedisClient, getRedisClient } from './lib/redis.js';
import { prisma } from './lib/db.js';
import apiRouter from './routes/index.js';
import { errorHandler } from './middleware/error.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { incrementMetric, recordRequestLatency, updateHealthStatus } from './lib/metrics.js';
import { AppError } from './lib/errors.js';

// Initialise Redis before any middleware runs so rate limiting is ready.
createRedisClient();

const app = express();

// Trust the configured number of upstream proxy hops so req.ip reflects the
// real client IP (not the proxy) when running behind Nginx or a load balancer.
// Set TRUST_PROXY=1 (or true / a CIDR list) in production.
if (config.TRUST_PROXY) {
  const v = config.TRUST_PROXY;
  const asNum = Number(v);
  if (!isNaN(asNum)) {
    app.set('trust proxy', asNum);
  } else if (v.toLowerCase() === 'true') {
    app.set('trust proxy', true);
  } else {
    // Treat as a comma-separated CIDR list or loopback/linklocal string
    app.set('trust proxy', v);
  }
}

// Security headers (Phase 1 audit fix — see docs/wpa-central-auth-api-complete-audit.md).
// Mounted before CORS/routes. crossOriginResourcePolicy is relaxed to
// 'cross-origin' for other allowed origins (admin panel, first-party apps)
// consuming this JSON API. Avatars are served from Backblaze B2 directly,
// not from this server.
// contentSecurityPolicy is disabled: this is a JSON API (not serving HTML
// pages), so a CSP designed for browser-rendered pages isn't applicable here
// and defaults could unexpectedly interfere with API responses/tools.
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

const allowedOrigins = config.ALLOWED_PUBLIC_ORIGINS.split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || origin === config.ADMIN_PANEL_ORIGIN) {
      return callback(null, true);
    }
    // A plain Error here previously fell through the global error handler's
    // catch-all branch and was returned as an opaque 500 "Internal Server
    // Error", which looks identical to an unrelated server bug from the
    // client's perspective. Using AppError gives callers a clear, correctly
    // classified 403 instead.
    return callback(new AppError('This origin is not allowed to access the API.', 'CORS_ORIGIN_NOT_ALLOWED', 403), false);
  },
  credentials: true,
}));

app.use(express.json());
// Avatars are served directly from Backblaze B2 (STORAGE_PUBLIC_URL) —
// no local /uploads/avatars static route needed.

// Request correlation + request logger middleware
app.use(requestIdMiddleware);
app.use((req, res, next) => {
  const startedAt = req.requestStartAt ?? Date.now();
  incrementMetric('requests_total');
  res.on('finish', () => {
    const durationMs = Date.now() - startedAt;
    recordRequestLatency(durationMs);
    if (res.statusCode >= 400) incrementMetric('errors_total');
    logger.info({
      requestId: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs,
      userId: (req as any).user?.id,
      clientId: (req as any).user?.clientId,
    }, 'HTTP request completed');
  });
  next();
});

// Root health check route at GET /health
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.get('/health/live', (_req, res) => {
  res.json({ status: 'UP', timestamp: new Date().toISOString() });
});

app.get('/health/ready', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    const redis = getRedisClient() ?? createRedisClient();
    if (redis) {
      await redis.ping();
      updateHealthStatus({ redis: 'UP', postgres: 'UP' });
    } else {
      updateHealthStatus({ redis: 'UNKNOWN', postgres: 'UP' });
    }
    res.json({ status: 'READY', timestamp: new Date().toISOString() });
  } catch (error) {
    updateHealthStatus({ postgres: 'DOWN' });
    res.status(503).json({ status: 'NOT_READY', timestamp: new Date().toISOString() });
  }
});

// Aggregate API prefix (/api/v1)
app.use(config.API_PREFIX, apiRouter);

// Standard Error Handler
app.use(errorHandler);

const server = app.listen(config.PORT, config.HOST, () => {
  logger.info(`Server running on http://${config.HOST}:${config.PORT}`);
});

async function gracefulShutdown(signal: string) {
  logger.info(`${signal} received, shutting down gracefully`);

  server.close(async () => {
    await closeRedisClient();
    await prisma.$disconnect();
    logger.info('Process terminated');
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
