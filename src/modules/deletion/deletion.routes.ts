import { Router, urlencoded } from 'express';
import { OAuthProvider, DeletionRequestType } from '@prisma/client';
import { z } from 'zod';
import { enterpriseRateLimit } from '../../lib/antiAbuse.js';
import { validateBody } from '../../middleware/validate.js';
import * as deletionService from './deletion.service.js';
import { config } from '../../config/index.js';

const router = Router();
const metaFormBody = urlencoded({ extended: false });

const publicDeletionRequestSchema = z.object({
  email: z.string().email(),
  requestType: z.nativeEnum(DeletionRequestType),
  provider: z.nativeEnum(OAuthProvider).optional(),
  explanation: z.string().max(500).optional(),
}).superRefine((value, ctx) => {
  if (value.requestType === DeletionRequestType.DATA && !value.provider) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Provider is required for provider data deletion requests.',
      path: ['provider'],
    });
  }
});

const confirmationCodeSchema = z.object({
  confirmationCode: z.string().min(8),
});

const signedRequestSchema = z.object({
  signed_request: z.string().min(1).optional(),
  signedRequest: z.string().min(1).optional(),
}).refine((value) => Boolean(value.signed_request || value.signedRequest), {
  message: 'signed_request is required.',
});

router.post(
  '/request',
  enterpriseRateLimit({
    route: 'public-deletion-request',
    windowMs: 60 * 60 * 1000,
    max: 6,
    identifierFrom: (req) => `${String(req.body?.email ?? '').toLowerCase()}:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`,
    threat: 'BOT_TRAFFIC_SPIKE',
    blockAfter: 8,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: 'both',
  }),
  validateBody(publicDeletionRequestSchema),
  async (req, res, next) => {
    try {
      const result = await deletionService.requestPublicDeletion({
        email: req.body.email,
        requestType: req.body.requestType,
        provider: req.body.provider ?? null,
        explanation: req.body.explanation ?? null,
        req,
      });
      res.status(202).json({
        success: true,
        message: 'Deletion request received. Use the confirmation code to check status.',
        request: {
          confirmationCode: result.request.confirmationCode,
          requestType: result.request.requestType,
          provider: result.request.provider,
          requestSource: result.request.requestSource,
          status: result.request.status,
          statusUrl: result.statusUrl,
          gracePeriodDeadlineAt: result.request.gracePeriodDeadlineAt,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

router.get(
  '/status/:confirmationCode',
  enterpriseRateLimit({
    route: 'public-deletion-status',
    windowMs: 15 * 60 * 1000,
    max: 20,
    identifierFrom: (req) => `${String(req.params?.confirmationCode ?? '').slice(0, 8)}:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`,
    threat: 'SUSPICIOUS_ACTIVITY_BLOCKED',
    blockAfter: 50,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: 'both',
  }),
  async (req, res, next) => {
    try {
      const { confirmationCode } = confirmationCodeSchema.parse(req.params);
      const status = await deletionService.getDeletionStatusByConfirmationCode(confirmationCode);
      res.json({ success: true, data: status });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  '/status/:confirmationCode/cancel',
  enterpriseRateLimit({
    route: 'public-deletion-cancel',
    windowMs: 60 * 60 * 1000,
    max: 6,
    identifierFrom: (req) => `${String(req.params?.confirmationCode ?? '').slice(0, 8)}:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`,
    threat: 'SUSPICIOUS_ACTIVITY_BLOCKED',
    blockAfter: 10,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: 'both',
  }),
  async (req, res, next) => {
    try {
      const { confirmationCode } = confirmationCodeSchema.parse(req.params);
      const cancelled = await deletionService.cancelDeletionRequestByConfirmationCode(confirmationCode, req);
      res.json({
        success: true,
        message: 'Deletion request cancelled.',
        data: {
          confirmationCode: cancelled.confirmationCode,
          status: cancelled.status,
          statusUrl: `${config.PUBLIC_WEBSITE_ORIGIN}/data-deletion/status/${cancelled.confirmationCode}`,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  '/meta/callback',
  metaFormBody,
  enterpriseRateLimit({
    route: 'meta-deletion-callback',
    windowMs: 60 * 60 * 1000,
    max: 60,
    identifierFrom: (req) => `${String(req.body?.signed_request ?? req.body?.signedRequest ?? '').slice(0, 16)}:${req.ip ?? req.socket.remoteAddress ?? 'unknown'}`,
    threat: 'SUSPICIOUS_ACTIVITY_BLOCKED',
    blockAfter: 120,
    blockTtlMs: 60 * 60 * 1000,
    blockScope: 'both',
  }),
  validateBody(signedRequestSchema),
  async (req, res, next) => {
    try {
      const signedRequest = req.body.signed_request ?? req.body.signedRequest;
      const result = await deletionService.requestMetaDeletionCallback({
        signedRequest,
        req,
      });
      res.json({
        confirmation_code: result.confirmation_code,
        url: result.url,
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
