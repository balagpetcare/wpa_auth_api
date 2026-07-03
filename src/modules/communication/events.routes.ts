import { Router } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../../lib/errors.js';
import { externalCommunicationEventSchema } from './events.schemas.js';
import {
  authenticateExternalCommunicationClient,
  enforceClientEventRateLimit,
  getOrCreateExternalCommunicationEvent,
  recordExternalCommunicationEventDuplicate,
} from './events.service.js';

const router = Router();

router.post('/events', async (req, res, next) => {
  try {
    const idempotencyKey = String(req.header('idempotency-key') ?? '').trim();
    if (!idempotencyKey) {
      throw new AppError('Invalid client credentials or event payload.', 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', 400);
    }

    const client = await authenticateExternalCommunicationClient(req);
    const payload = externalCommunicationEventSchema.parse(req.body);

    await enforceClientEventRateLimit(client.id, payload.event, req);

    const outcome = await getOrCreateExternalCommunicationEvent({
      req,
      client,
      payload,
      idempotencyKey,
    });

    if ('existing' in outcome && outcome.existing) {
      const deduped = await recordExternalCommunicationEventDuplicate({ existing: outcome.existing });
      res.json({ success: true, data: deduped });
      return;
    }

    res.status(202).json({ success: true, data: outcome.result });
  } catch (error) {
    if (error instanceof AppError) {
      res.status(error.status).json({ success: false, code: error.code, message: error.message });
      return;
    }
    if (error instanceof ZodError) {
      res.status(400).json({ success: false, code: 'INVALID_CLIENT_OR_EVENT_OR_PAYLOAD', message: 'Invalid client credentials or event payload.' });
      return;
    }
    next(error);
  }
});

export default router;
