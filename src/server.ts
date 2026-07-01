import express from 'express';
import cors from 'cors';
import { config } from './config/index.js';
import { logger } from './lib/logger.js';
import { createRedisClient, closeRedisClient } from './lib/redis.js';
import { prisma } from './lib/db.js';
import apiRouter from './routes/index.js';
import { errorHandler } from './middleware/error.js';
import { ensureAvatarDirectory, getAvatarDirectory } from './lib/avatarStorage.js';
import { startQueueProcessor, stopQueueProcessor } from './lib/emailQueueProcessor.js';

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

const allowedOrigins = config.ALLOWED_PUBLIC_ORIGINS.split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || origin === config.ADMIN_PANEL_ORIGIN) {
      return callback(null, true);
    }
    return callback(new Error('CORS Policy: Origin not allowed'), false);
  },
  credentials: true,
}));

app.use(express.json());
void ensureAvatarDirectory();
app.use('/uploads/avatars', express.static(getAvatarDirectory(), {
  fallthrough: false,
  index: false,
  maxAge: '1d',
}));

// Request logger middleware
app.use((req, res, next) => {
  logger.info({ method: req.method, url: req.url }, 'Incoming request');
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

// Aggregate API prefix (/api/v1)
app.use(config.API_PREFIX, apiRouter);

// Standard Error Handler
app.use(errorHandler);

const server = app.listen(config.PORT, config.HOST, () => {
  logger.info(`Server running on http://${config.HOST}:${config.PORT}`);
  // Start email queue processor
  startQueueProcessor().catch((error) => {
    const errorMsg = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMsg }, 'Failed to start email queue processor');
  });
});

async function gracefulShutdown(signal: string) {
  logger.info(`${signal} received, shutting down gracefully`);

  // Stop queue processor first
  await stopQueueProcessor();

  server.close(async () => {
    await closeRedisClient();
    await prisma.$disconnect();
    logger.info('Process terminated');
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
