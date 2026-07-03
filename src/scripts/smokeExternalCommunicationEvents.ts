import express from 'express';
import crypto from 'crypto';
import apiRouter from '../routes/index.js';
import { prisma } from '../lib/db.js';
import { AppError } from '../lib/errors.js';

function sha256(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function main() {
  const app = express();
  app.use(express.json());
  app.use('/api/v1', apiRouter);
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err instanceof AppError) {
      res.status(err.status).json({ success: false, code: err.code, message: err.message });
      return;
    }
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: err instanceof Error ? err.message : 'Internal error' });
  });

  const server = await new Promise<import('http').Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to start smoke server.');
  }

  const baseUrl = `http://127.0.0.1:${address.port}`;

  const missingIdempotency = await fetch(`${baseUrl}/api/v1/communication/events`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ event: 'VACCINATION_PAYMENT_CONFIRMED' }),
  });
  const missingIdempotencyBody = await missingIdempotency.json() as any;
  if (missingIdempotency.status !== 400 || missingIdempotencyBody.code !== 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD') {
    throw new Error(`Expected missing Idempotency-Key to fail safely. Got ${missingIdempotency.status} ${JSON.stringify(missingIdempotencyBody)}`);
  }

  const missingAuth = await fetch(`${baseUrl}/api/v1/communication/events`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': 'smoke-no-auth',
    },
    body: JSON.stringify({ event: 'VACCINATION_PAYMENT_CONFIRMED' }),
  });
  const missingAuthBody = await missingAuth.json() as any;
  if (missingAuth.status !== 401 || missingAuthBody.code !== 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD') {
    throw new Error(`Expected missing Authorization to fail safely. Got ${missingAuth.status} ${JSON.stringify(missingAuthBody)}`);
  }

  const originalFindUnique = prisma.authClient.findUnique.bind(prisma.authClient);
  try {
    (prisma.authClient as any).findUnique = async () => ({
      id: 'clt_smoke_1',
      clientId: 'smoke-client',
      clientSecretHash: sha256('smoke-secret'),
      type: 'SERVICE',
      status: 'ACTIVE',
      allowedScopes: ['communication:events'],
      name: 'Smoke Client',
    });

    const invalidEvent = await fetch(`${baseUrl}/api/v1/communication/events`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-client-id': 'smoke-client',
        authorization: 'Bearer smoke-secret',
        'idempotency-key': 'smoke-invalid-event',
      },
      body: JSON.stringify({
        event: 'NOT_SUPPORTED',
        channels: ['sms'],
        recipient: { phone: '01701022274' },
        data: { bookingRef: 'X', paymentRef: 'Y', amount: 1, currency: 'BDT', campaignName: 'Smoke' },
      }),
    });
    const invalidEventBody = await invalidEvent.json() as any;
    if (invalidEvent.status !== 400 || invalidEventBody.code !== 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD') {
      throw new Error(`Expected invalid event to fail safely. Got ${invalidEvent.status} ${JSON.stringify(invalidEventBody)}`);
    }
  } finally {
    (prisma.authClient as any).findUnique = originalFindUnique;
  }

  server.close();
  console.log('PASS: communication event route smoke checks completed successfully.');
}

main().catch((error) => {
  console.error('FAIL: communication event route smoke checks failed.');
  console.error(error);
  process.exit(1);
});
