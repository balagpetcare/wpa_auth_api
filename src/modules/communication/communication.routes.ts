import { Router } from 'express';
import { z } from 'zod';
import {
  CommunicationChannel,
  CommunicationDeliveryStatus,
  CommunicationProviderStatus,
  CommunicationPurpose,
  OtpTemplateLanguage,
  OtpTemplatePurpose,
} from '@prisma/client';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { requireAdmin } from '../../middleware/requireRole.js';
import { validateBody } from '../../middleware/validate.js';
import { requirePermission } from '../../middleware/requirePermission.js';
import { sendTestEmailRateLimit } from '../../middleware/rateLimit.js';
import * as communicationService from './communication.service.js';

const router = Router();
router.use(authGuard, requireAdmin);

const providerSchema = z.object({
  name: z.string().min(2).max(120),
  code: z.string().min(2).max(80),
  type: z.nativeEnum(CommunicationChannel),
  status: z.nativeEnum(CommunicationProviderStatus).optional(),
  environment: z.enum(['SANDBOX', 'LIVE']).optional(),
  isGlobal: z.boolean().optional(),
  countryCode: z.string().regex(/^\d{1,4}$/).nullable().optional(),
  priority: z.number().int().min(0).max(9999).optional(),
  supportedPurposes: z.array(z.nativeEnum(CommunicationPurpose)).min(1),
  dailyLimit: z.number().int().positive().nullable().optional(),
  monthlyLimit: z.number().int().positive().nullable().optional(),
  rateLimitPerMinute: z.number().int().positive().nullable().optional(),
});

const credentialSchema = z.object({
  secrets: z.record(z.string(), z.string().min(1)),
  apiBaseUrl: z.string().url().nullable().optional(),
  senderId: z.string().max(64).nullable().optional(),
  fromName: z.string().max(120).nullable().optional(),
  fromEmail: z.string().email().nullable().optional(),
  smtpHost: z.string().max(255).nullable().optional(),
  smtpPort: z.number().int().min(1).max(65535).nullable().optional(),
  smtpSecure: z.boolean().nullable().optional(),
  isActive: z.boolean().optional(),
});

const routingRuleSchema = z.object({
  // Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md):
  // null/omitted = system-wide default rule (existing behavior, unchanged).
  appId: z.string().nullable().optional(),
  channel: z.nativeEnum(CommunicationChannel),
  countryCode: z.string().regex(/^\d{1,4}$/).nullable().optional(),
  purpose: z.nativeEnum(CommunicationPurpose),
  language: z.nativeEnum(OtpTemplateLanguage).nullable().optional(),
  providerId: z.string().nullable().optional(),
  fallbackProviderIds: z.array(z.string()).nullable().optional(),
  priority: z.number().int().min(0).max(9999).optional(),
  enabled: z.boolean().optional(),
  fallbackEnabled: z.boolean().optional(),
  environment: z.enum(['SANDBOX', 'LIVE']).nullable().optional(),
  isActive: z.boolean().optional(),
});

const templateSchema = z.object({
  channel: z.nativeEnum(CommunicationChannel),
  purpose: z.nativeEnum(OtpTemplatePurpose),
  language: z.nativeEnum(OtpTemplateLanguage),
  subject: z.string().max(255).nullable().optional(),
  body: z.string().min(5),
  variables: z.array(z.string()).nullable().optional(),
  isDefault: z.boolean().optional(),
  isActive: z.boolean().optional(),
});

const providerListQuerySchema = z.object({
  type: z.nativeEnum(CommunicationChannel).optional(),
});

const deliveryLogQuerySchema = z.object({
  channel: z.nativeEnum(CommunicationChannel).optional(),
  providerId: z.string().optional(),
  status: z.nativeEnum(CommunicationDeliveryStatus).optional(),
  recipient: z.string().optional(),
  countryCode: z.string().optional(),
  limit: z.coerce.number().min(1).max(100).optional().default(50),
});

const testSmsSchema = z.object({
  to: z.string().min(8),
  message: z.string().min(3).max(500).optional(),
});

const testEmailSchema = z.object({
  to: z.string().email(),
  subject: z.string().min(3).max(255).optional(),
  message: z.string().min(3).max(5000).optional(),
});

router.get(
  '/providers',
  requirePermission('communication.providers.read'),
  async (req, res, next) => {
    try {
      const query = providerListQuerySchema.parse(req.query);
      const providers = await communicationService.listProviders(query);
      res.json({ success: true, data: { items: providers } });
    } catch (error) {
      next(error);
    }
  },
);

router.get(
  '/providers/:id',
  requirePermission('communication.providers.read'),
  async (req, res, next) => {
    try {
      const provider = await communicationService.formatProviderResponse(req.params.id);
      res.json({ success: true, data: provider });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/providers',
  requirePermission('communication.providers.create'),
  validateBody(providerSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const provider = await communicationService.createOrUpdateProvider({
        actorId: req.user!.id,
        req,
        data: req.body,
      });
      res.status(201).json({ success: true, data: provider, message: 'Communication provider created successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.patch(
  '/providers/:id',
  requirePermission('communication.providers.update'),
  validateBody(providerSchema.partial().extend({
    supportedPurposes: z.array(z.nativeEnum(CommunicationPurpose)).min(1).optional(),
  })),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const current = await communicationService.getProviderById(req.params.id);
      const provider = await communicationService.createOrUpdateProvider({
        actorId: req.user!.id,
        req,
        providerId: req.params.id,
        data: {
          name: req.body.name ?? current.name,
          code: req.body.code ?? current.code,
          type: req.body.type ?? current.type,
          status: req.body.status ?? current.status,
          environment: req.body.environment ?? current.environment,
          isGlobal: req.body.isGlobal ?? current.isGlobal,
          countryCode: req.body.countryCode === undefined ? current.countryCode : req.body.countryCode,
          priority: req.body.priority ?? current.priority,
          supportedPurposes: req.body.supportedPurposes ?? current.supportedPurposes,
          dailyLimit: req.body.dailyLimit === undefined ? current.dailyLimit : req.body.dailyLimit,
          monthlyLimit: req.body.monthlyLimit === undefined ? current.monthlyLimit : req.body.monthlyLimit,
          rateLimitPerMinute: req.body.rateLimitPerMinute === undefined ? current.rateLimitPerMinute : req.body.rateLimitPerMinute,
        },
      });
      res.json({ success: true, data: provider, message: 'Communication provider updated successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.delete(
  '/providers/:id',
  requirePermission('communication.providers.delete'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const provider = await communicationService.softDeleteProvider(req.params.id, req.user!.id, req);
      res.json({ success: true, data: provider, message: 'Communication provider deleted successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/providers/:id/activate',
  requirePermission('communication.providers.update'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const provider = await communicationService.setProviderStatus(req.params.id, 'ACTIVE', req.user!.id, req);
      res.json({ success: true, data: provider, message: 'Communication provider activated successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/providers/:id/deactivate',
  requirePermission('communication.providers.update'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const provider = await communicationService.setProviderStatus(req.params.id, 'INACTIVE', req.user!.id, req);
      res.json({ success: true, data: provider, message: 'Communication provider deactivated successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/providers/:id/credentials',
  requirePermission('communication.credentials.manage'),
  validateBody(credentialSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const credential = await communicationService.upsertProviderCredential({
        providerId: req.params.id,
        actorId: req.user!.id,
        req,
        data: req.body,
      });
      res.status(201).json({ success: true, data: credential, message: 'Provider credentials saved successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.patch(
  '/providers/:id/credentials/:credentialId',
  requirePermission('communication.credentials.manage'),
  validateBody(credentialSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const credential = await communicationService.upsertProviderCredential({
        providerId: req.params.id,
        actorId: req.user!.id,
        req,
        credentialId: req.params.credentialId,
        data: req.body,
      });
      res.json({ success: true, data: credential, message: 'Provider credentials updated successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

// Phase 2 fix (docs/phase-2-core-identity-admin-modules.md): sendTestEmailRateLimit
// already existed in middleware/rateLimit.ts but was never wired to a route.
// Applied here (and to test-sms) so repeated "test" clicks can't be used to
// mass-send real messages to arbitrary recipients through a live provider.
router.post(
  '/providers/:id/test-sms',
  requirePermission('communication.providers.test'),
  sendTestEmailRateLimit,
  validateBody(testSmsSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await communicationService.testProvider(req.params.id, req.user!.id, req, req.body);
      res.json({ success: result.success, data: result, message: result.success ? 'SMS provider test completed successfully.' : 'SMS provider test failed.' });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/providers/:id/test-email',
  requirePermission('communication.providers.test'),
  sendTestEmailRateLimit,
  validateBody(testEmailSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const result = await communicationService.testProvider(req.params.id, req.user!.id, req, req.body);
      res.json({ success: result.success, data: result, message: result.success ? 'Email provider test completed successfully.' : 'Email provider test failed.' });
    } catch (error) {
      next(error);
    }
  },
);

router.get(
  '/routing-rules',
  requirePermission('communication.routing.read'),
  async (_req, res, next) => {
    try {
      const items = await communicationService.listRoutingRules();
      res.json({ success: true, data: { items } });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/routing-rules',
  requirePermission('communication.routing.manage'),
  validateBody(routingRuleSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const rule = await communicationService.upsertRoutingRule({
        actorId: req.user!.id,
        req,
        data: req.body,
      });
      res.status(201).json({ success: true, data: rule, message: 'Routing rule created successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.patch(
  '/routing-rules/:id',
  requirePermission('communication.routing.manage'),
  validateBody(routingRuleSchema.partial()),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const current = await communicationService.listRoutingRules();
      const existing = current.find((item) => item.id === req.params.id);
      if (!existing) {
        res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Routing rule not found.' });
        return;
      }
      const rule = await communicationService.upsertRoutingRule({
        actorId: req.user!.id,
        req,
        ruleId: req.params.id,
        data: {
          appId: req.body.appId === undefined ? existing.appId : req.body.appId,
          channel: req.body.channel ?? existing.channel,
          countryCode: req.body.countryCode === undefined ? existing.countryCode : req.body.countryCode,
          purpose: req.body.purpose ?? existing.purpose,
          language: req.body.language === undefined ? existing.language : req.body.language,
          providerId: req.body.providerId === undefined ? existing.providerId : req.body.providerId,
          fallbackProviderIds: req.body.fallbackProviderIds === undefined ? ((existing.fallbackProviderIds as string[] | null) ?? []) : req.body.fallbackProviderIds,
          priority: req.body.priority ?? existing.priority,
          enabled: req.body.enabled === undefined ? (existing as any).enabled : req.body.enabled,
          fallbackEnabled: req.body.fallbackEnabled === undefined ? (existing as any).fallbackEnabled : req.body.fallbackEnabled,
          environment: req.body.environment === undefined ? (existing as any).environment : req.body.environment,
          isActive: req.body.isActive ?? existing.isActive,
        },
      });
      res.json({ success: true, data: rule, message: 'Routing rule updated successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.delete(
  '/routing-rules/:id',
  requirePermission('communication.routing.manage'),
  async (_req, res, next) => {
    try {
      await communicationService.deleteRoutingRule(_req.params.id);
      res.json({ success: true, message: 'Routing rule deleted successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.get(
  '/templates',
  requirePermission('communication.templates.read'),
  async (_req, res, next) => {
    try {
      const items = await communicationService.listOtpTemplates();
      res.json({ success: true, data: { items } });
    } catch (error) {
      next(error);
    }
  },
);

router.post(
  '/templates',
  requirePermission('communication.templates.manage'),
  validateBody(templateSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const template = await communicationService.upsertOtpTemplate({
        actorId: req.user!.id,
        req,
        data: req.body,
      });
      res.status(201).json({ success: true, data: template, message: 'OTP template created successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.patch(
  '/templates/:id',
  requirePermission('communication.templates.manage'),
  validateBody(templateSchema.partial().extend({ body: z.string().min(5).optional() })),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const current = await communicationService.listOtpTemplates();
      const existing = current.find((item) => item.id === req.params.id);
      if (!existing) {
        res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'OTP template not found.' });
        return;
      }
      const template = await communicationService.upsertOtpTemplate({
        actorId: req.user!.id,
        req,
        templateId: req.params.id,
        data: {
          channel: req.body.channel ?? existing.channel,
          purpose: req.body.purpose ?? existing.purpose,
          language: req.body.language ?? existing.language,
          subject: req.body.subject === undefined ? existing.subject : req.body.subject,
          body: req.body.body ?? existing.body,
          variables: req.body.variables === undefined ? ((existing.variables as string[] | null) ?? []) : req.body.variables,
          isDefault: req.body.isDefault ?? existing.isDefault,
          isActive: req.body.isActive ?? existing.isActive,
        },
      });
      res.json({ success: true, data: template, message: 'OTP template updated successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.delete(
  '/templates/:id',
  requirePermission('communication.templates.manage'),
  async (req, res, next) => {
    try {
      await communicationService.deleteOtpTemplate(req.params.id);
      res.json({ success: true, message: 'OTP template deleted successfully.' });
    } catch (error) {
      next(error);
    }
  },
);

router.get(
  '/delivery-logs',
  requirePermission('communication.logs.read'),
  async (req, res, next) => {
    try {
      const query = deliveryLogQuerySchema.parse(req.query);
      const data = await communicationService.getDeliveryLogs({
        ...query,
        cursor: typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined,
      });
      res.json({ success: true, data });
    } catch (error) {
      next(error);
    }
  },
);

router.get(
  '/provider-audit-logs',
  requirePermission('communication.logs.read'),
  async (req, res, next) => {
    try {
      const limit = Math.min(Number(req.query['limit'] ?? 50), 100);
      const cursor = typeof req.query['cursor'] === 'string' ? req.query['cursor'] : undefined;
      const data = await communicationService.getProviderAuditLogs({ limit, cursor });
      res.json({ success: true, data });
    } catch (error) {
      next(error);
    }
  },
);

router.get(
  '/provider-health',
  requirePermission('communication.health.read'),
  async (_req, res, next) => {
    try {
      const items = await communicationService.getProviderHealth();
      res.json({ success: true, data: { items } });
    } catch (error) {
      next(error);
    }
  },
);

export default router;
