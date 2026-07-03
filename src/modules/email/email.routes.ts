/**
 * Email Management Routes
 * Admin API for managing email branding and templates
 */

import { Router } from 'express';
import { z } from 'zod';
import { authGuard, AuthenticatedRequest } from '../../middleware/auth.js';
import { requireAdmin } from '../../middleware/requireRole.js';
import { requirePermission } from '../../middleware/requirePermission.js';
import { validateBody } from '../../middleware/validate.js';
import { emailBrandingRateLimit, sendTestEmailRateLimit } from '../../middleware/rateLimit.js';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { renderEmailTemplate } from '../../lib/emailRenderer.js';
import { sendEmail } from '../../lib/mailer.js';
import { writeAuditLog } from '../../lib/audit.js';

const router = Router();

// All email routes require authentication and admin role
router.use(authGuard, requireAdmin);

// ─── Schemas ─────────────────────────────────────────────────────────────────

const emailBrandingUpdateSchema = z.object({
  brandName: z.string().min(1).max(255).optional(),
  logoUrl: z.string().url().optional().nullable(),
  logoAltText: z.string().max(255).optional().nullable(),
  primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().nullable(),
  textColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().nullable(),
  headerBackgroundColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().nullable(),
  footerBackgroundColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().nullable(),
  supportEmail: z.string().email().optional().nullable(),
  supportPhone: z.string().max(20).optional().nullable(),
  websiteUrl: z.string().url().optional().nullable(),
  privacyUrl: z.string().url().optional().nullable(),
  termsUrl: z.string().url().optional().nullable(),
  helpUrl: z.string().url().optional().nullable(),
  contactUrl: z.string().url().optional().nullable(),
  facebookUrl: z.string().url().optional().nullable(),
  instagramUrl: z.string().url().optional().nullable(),
  linkedinUrl: z.string().url().optional().nullable(),
  twitterUrl: z.string().url().optional().nullable(),
  youtubeUrl: z.string().url().optional().nullable(),
  tiktokUrl: z.string().url().optional().nullable(),
  footerText: z.string().max(500).optional().nullable(),
  address: z.string().max(500).optional().nullable(),
  legalDisclaimer: z.string().max(1000).optional().nullable(),
  // Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md)
  replyTo: z.string().email().optional().nullable(),
});

// Phase 2.6A: per-app branding update schema — same field set as
// ClientBranding, validated the same way as the global schema above.
const clientBrandingUpdateSchema = z.object({
  logoUrl: z.string().url().optional().nullable(),
  logoAltText: z.string().max(255).optional().nullable(),
  brandColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().nullable(),
  accentColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().nullable(),
  senderName: z.string().max(255).optional().nullable(),
  senderEmail: z.string().email().optional().nullable(),
  replyTo: z.string().email().optional().nullable(),
  supportEmail: z.string().email().optional().nullable(),
  supportPhone: z.string().max(20).optional().nullable(),
  websiteUrl: z.string().url().optional().nullable(),
  privacyUrl: z.string().url().optional().nullable(),
  termsUrl: z.string().url().optional().nullable(),
  unsubscribeUrl: z.string().url().optional().nullable(),
  footerText: z.string().max(500).optional().nullable(),
  isActive: z.boolean().optional(),
});

const emailTemplateUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  subject: z.string().min(1).max(255).optional(),
  preheader: z.string().max(255).optional().nullable(),
  htmlBody: z.string().min(1).optional(),
  textBody: z.string().optional().nullable(),
  variables: z.object({
    required: z.array(z.string()).optional(),
    optional: z.array(z.string()).optional(),
  }).optional().nullable(),
});

const templatePreviewSchema = z.object({
  variables: z.record(z.any()),
});

const sendTestEmailSchema = z.object({
  testEmail: z.string().email(),
  variables: z.record(z.any()).optional(),
});

// ─── Email Branding ──────────────────────────────────────────────────────────

/**
 * GET /admin/email-branding
 * Get current active email branding settings
 */
router.get(
  '/email-branding',
  requirePermission('email_branding.read'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const branding = await prisma.emailBrandingSetting.findFirst({
        where: { isActive: true },
      });

      if (!branding) {
        res.status(404).json({
          success: false,
          message: 'No active email branding found',
          code: 'NOT_FOUND',
        });
        return;
      }

      res.json({ success: true, data: branding });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * PATCH /admin/email-branding
 * Update email branding settings
 */
router.patch(
  '/email-branding',
  requirePermission('email_branding.update'),
  emailBrandingRateLimit,
  validateBody(emailBrandingUpdateSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const branding = await prisma.emailBrandingSetting.findFirst({
        where: { isActive: true },
      });

      if (!branding) {
        throw new AppError('No active email branding found', 'NOT_FOUND', 404);
      }

      // Track original values for audit
      const originalValues = {
        brandName: branding.brandName,
        supportEmail: branding.supportEmail,
        websiteUrl: branding.websiteUrl,
      };

      const updated = await prisma.emailBrandingSetting.update({
        where: { id: branding.id },
        data: {
          ...req.body,
          updatedByAdminId: req.user!.id,
        },
      });

      // Log audit trail (without sensitive data in changed fields)
      await writeAuditLog({
        userId: req.user!.id,
        action: 'PROFILE_UPDATED',
        metadata: {
          type: 'email_branding',
          fields: Object.keys(req.body),
          previousValues: originalValues,
        },
        req,
      });

      res.json({
        success: true,
        message: 'Email branding updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ─── Email Templates ─────────────────────────────────────────────────────────

/**
 * GET /admin/email-templates
 * List all email templates
 */
// Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md):
// added an optional ?clientId= filter and clientId/locale/version to the
// projection — the underlying data (EmailTemplate.clientId) already
// supported per-app overrides, but the list endpoint didn't expose enough
// to distinguish a global default from an app-specific override, or to
// filter down to just one app's rows for the new Template Overrides UI.
// clientId=global returns only the system-default (clientId: null) rows.
const emailTemplateListQuerySchema = z.object({
  clientId: z.string().optional(),
});

router.get(
  '/email-templates',
  requirePermission('email_template.read'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const query = emailTemplateListQuerySchema.parse(req.query);
      const where =
        query.clientId === 'global' ? { clientId: null } : query.clientId ? { clientId: query.clientId } : {};

      const templates = await prisma.emailTemplate.findMany({
        where,
        orderBy: { key: 'asc' },
        select: {
          id: true,
          key: true,
          name: true,
          subject: true,
          preheader: true,
          isActive: true,
          clientId: true,
          locale: true,
          version: true,
          updatedByAdminId: true,
          updatedAt: true,
          createdAt: true,
        },
      });

      res.json({ success: true, data: { items: templates, total: templates.length } });
    } catch (error) {
      next(error);
    }
  }
);

// Phase 2.6A: previously there was no way to create a new app-specific
// template override — only PATCH on an existing row by id. This creates a
// new EmailTemplate row scoped to a clientId (or clientId: null for a new
// global-default key), reusing the existing key+locale+clientId unique
// constraint already defined in the schema.
const emailTemplateCreateSchema = z.object({
  key: z.string().min(1).max(120),
  clientId: z.string().nullable().optional(),
  locale: z.string().min(2).max(10).optional().default('en'),
  name: z.string().min(1).max(255),
  subject: z.string().min(1).max(255),
  preheader: z.string().max(255).optional().nullable(),
  htmlBody: z.string().min(1),
  textBody: z.string().optional().nullable(),
  variables: z
    .object({
      required: z.array(z.string()).optional(),
      optional: z.array(z.string()).optional(),
    })
    .optional()
    .nullable(),
});

router.post(
  '/email-templates',
  requirePermission('email_template.update'),
  emailBrandingRateLimit,
  validateBody(emailTemplateCreateSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      if (req.body.clientId) {
        const client = await prisma.authClient.findUnique({ where: { id: req.body.clientId } });
        if (!client) throw new AppError('Client not found.', 'NOT_FOUND', 404);
      }

      const existing = await prisma.emailTemplate.findUnique({
        where: { key_locale_clientId: { key: req.body.key, locale: req.body.locale, clientId: req.body.clientId ?? null } },
      });
      if (existing) {
        throw new AppError('A template with this key/locale already exists for this scope.', 'ALREADY_EXISTS', 409);
      }

      const created = await prisma.emailTemplate.create({
        data: { ...req.body, updatedByAdminId: req.user!.id },
      });

      await prisma.emailTemplateAuditLog.create({
        data: {
          templateId: created.id,
          action: 'CREATE',
          changedFields: { key: created.key, clientId: created.clientId, locale: created.locale },
          actorAdminId: req.user!.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        },
      });

      res.status(201).json({ success: true, message: 'Template override created successfully.', data: created });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * GET /admin/email-templates/:id
 * Get a specific email template
 */
router.get(
  '/email-templates/:id',
  requirePermission('email_template.read'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const template = await prisma.emailTemplate.findUnique({
        where: { id: req.params.id },
      });

      if (!template) {
        throw new AppError('Email template not found', 'NOT_FOUND', 404);
      }

      res.json({ success: true, data: template });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * PATCH /admin/email-templates/:id
 * Update an email template
 */
router.patch(
  '/email-templates/:id',
  requirePermission('email_template.update'),
  emailBrandingRateLimit,
  validateBody(emailTemplateUpdateSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const template = await prisma.emailTemplate.findUnique({
        where: { id: req.params.id },
      });

      if (!template) {
        throw new AppError('Email template not found', 'NOT_FOUND', 404);
      }

      // Store original for audit log
      const originalSubject = template.subject;

      const updated = await prisma.emailTemplate.update({
        where: { id: req.params.id },
        data: {
          ...req.body,
          updatedByAdminId: req.user!.id,
        },
      });

      // Create audit log entry
      const changedFields: Record<string, any> = {};
      if (req.body.subject) {
        changedFields.subject = { old: originalSubject, new: req.body.subject };
      }
      if (req.body.name) {
        changedFields.name = { old: template.name, new: req.body.name };
      }
      // Note: Don't log htmlBody or textBody (could contain sensitive content)

      await prisma.emailTemplateAuditLog.create({
        data: {
          templateId: req.params.id,
          action: 'UPDATE',
          changedFields: changedFields,
          actorAdminId: req.user!.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        },
      });

      res.json({
        success: true,
        message: 'Email template updated successfully',
        data: updated,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * POST /admin/email-templates/:id/preview
 * Preview a template with sample variables
 */
router.post(
  '/email-templates/:id/preview',
  requirePermission('email_template.preview'),
  validateBody(templatePreviewSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const template = await prisma.emailTemplate.findUnique({
        where: { id: req.params.id },
      });

      if (!template) {
        throw new AppError('Email template not found', 'NOT_FOUND', 404);
      }

      // Render with provided variables
      const rendered = await renderEmailTemplate(template.key as any, req.body.variables || {});

      res.json({
        success: true,
        data: {
          template: template.key,
          rendered: {
            subject: rendered.subject,
            preheader: rendered.preheader,
            html: rendered.html,
            text: rendered.text,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * POST /admin/email-templates/:id/send-test
 * Send a test email with the template
 */
router.post(
  '/email-templates/:id/send-test',
  requirePermission('email_template.send_test'),
  sendTestEmailRateLimit,
  validateBody(sendTestEmailSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const template = await prisma.emailTemplate.findUnique({
        where: { id: req.params.id },
      });

      if (!template) {
        throw new AppError('Email template not found', 'NOT_FOUND', 404);
      }

      // Render template
      const rendered = await renderEmailTemplate(template.key as any, req.body.variables || {});

      // Send test email
      await sendEmail(
        req.body.testEmail,
        `[TEST] ${rendered.subject}`,
        rendered.text,
        rendered.html,
        'GENERAL'
      );

      // Log the test send (without sensitive variables)
      await writeAuditLog({
        userId: req.user!.id,
        action: 'PROFILE_UPDATED',
        metadata: {
          type: 'email_template_test',
          testEmail: req.body.testEmail,
          templateKey: template.key,
        },
        req,
      });

      res.json({
        success: true,
        message: `Test email sent to ${req.body.testEmail}`,
        data: {
          template: template.key,
          recipient: req.body.testEmail,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * POST /admin/email-templates/:id/reset-default
 * Reset a template to its default/seeded values
 */
router.post(
  '/email-templates/:id/reset-default',
  requirePermission('email_template.reset'),
  emailBrandingRateLimit,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const { DEFAULT_EMAIL_TEMPLATES } = await import('../../lib/defaultEmailTemplates.js');

      const template = await prisma.emailTemplate.findUnique({
        where: { id: req.params.id },
      });

      if (!template) {
        throw new AppError('Email template not found', 'NOT_FOUND', 404);
      }

      // Find the default template matching this template's key
      const defaultTemplate = DEFAULT_EMAIL_TEMPLATES.find(
        (t: any) => t.key === template.key
      );

      if (!defaultTemplate) {
        throw new AppError(
          `No default template found for key: ${template.key}`,
          'NOT_FOUND',
          404
        );
      }

      // Record the changes for audit log
      const changedFields: Record<string, any> = {};
      if (template.subject !== defaultTemplate.subject) {
        changedFields.subject = {
          old: template.subject,
          new: defaultTemplate.subject,
        };
      }
      if (template.preheader !== defaultTemplate.preheader) {
        changedFields.preheader = {
          old: template.preheader,
          new: defaultTemplate.preheader,
        };
      }
      if (template.htmlBody !== defaultTemplate.htmlBody) {
        changedFields.htmlBody = {
          old: template.htmlBody?.substring(0, 100),
          new: defaultTemplate.htmlBody?.substring(0, 100),
        };
      }
      if (template.textBody !== defaultTemplate.textBody) {
        changedFields.textBody = {
          old: template.textBody?.substring(0, 100),
          new: defaultTemplate.textBody?.substring(0, 100),
        };
      }
      if (JSON.stringify(template.variables) !== JSON.stringify(defaultTemplate.variables)) {
        changedFields.variables = {
          old: template.variables,
          new: defaultTemplate.variables,
        };
      }

      // Update the template with default values
      const updatedTemplate = await prisma.emailTemplate.update({
        where: { id: template.id },
        data: {
          name: defaultTemplate.name,
          subject: defaultTemplate.subject,
          preheader: defaultTemplate.preheader,
          htmlBody: defaultTemplate.htmlBody,
          textBody: defaultTemplate.textBody,
          variables: defaultTemplate.variables,
        },
      });

      // Create audit log entry
      if (req.user) {
        await prisma.emailTemplateAuditLog.create({
          data: {
            templateId: template.id,
            action: 'RESET',
            changedFields,
            actorAdminId: req.user.id,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
          },
        });
      }

      res.json({
        success: true,
        data: updatedTemplate,
        message: `Template "${defaultTemplate.name}" has been reset to default successfully`,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ─── Template Versioning & Rollback ──────────────────────────────────────────

/**
 * GET /admin/email-templates/:id/versions
 * Get version history for a template
 */
router.get(
  '/email-templates/:id/versions',
  requirePermission('email_template.read'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const versions = await prisma.emailTemplateVersion.findMany({
        where: { templateId: req.params.id },
        orderBy: { version: 'desc' },
      });

      if (versions.length === 0) {
        throw new AppError('No versions found for this template', 'NOT_FOUND', 404);
      }

      res.json({
        success: true,
        data: { items: versions },
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * POST /admin/email-templates/:id/rollback/:versionId
 * Rollback template to a previous version
 */
router.post(
  '/email-templates/:id/rollback/:versionId',
  requirePermission('email_template.rollback'),
  emailBrandingRateLimit,
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const template = await prisma.emailTemplate.findUnique({
        where: { id: req.params.id },
      });

      if (!template) {
        throw new AppError('Template not found', 'NOT_FOUND', 404);
      }

      const version = await prisma.emailTemplateVersion.findUnique({
        where: {
          templateId_version: {
            templateId: req.params.id,
            version: parseInt(req.params.versionId),
          },
        },
      });

      if (!version) {
        throw new AppError('Version not found', 'NOT_FOUND', 404);
      }

      // Create audit log for rollback
      await prisma.emailTemplateAuditLog.create({
        data: {
          templateId: template.id,
          action: 'ROLLBACK',
          fromVersion: template.version,
          toVersion: version.version,
          changedFields: {
            subject: { from: template.subject, to: version.subject },
            htmlBody: { fromLength: template.htmlBody.length, toLength: version.htmlBody.length },
          },
          actorAdminId: req.user?.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        },
      });

      // Update template with version content
      const updated = await prisma.emailTemplate.update({
        where: { id: template.id },
        data: {
          name: version.name,
          subject: version.subject,
          preheader: version.preheader,
          htmlBody: version.htmlBody,
          textBody: version.textBody,
          variables: version.variables as any,
        },
      });

      res.json({
        success: true,
        data: updated,
        message: `Template rolled back to version ${version.version}`,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ─── Template Validation ─────────────────────────────────────────────────────

/**
 * POST /admin/email-templates/validate
 * Validate template before save
 */
router.post(
  '/email-templates/validate',
  requirePermission('email_template.create'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const { EmailTemplateValidator } = await import('../../lib/emailTemplateValidator.js');

      const result = EmailTemplateValidator.validate({
        name: req.body.name,
        subject: req.body.subject,
        htmlBody: req.body.htmlBody,
        textBody: req.body.textBody,
        variables: req.body.variables,
      });

      res.json({
        success: true,
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }
);

// ─── Client Branding ────────────────────────────────────────────────────────

/**
 * GET /admin/clients/:clientId/branding
 * Get branding for a specific client/app
 */
router.get(
  '/clients/:clientId/branding',
  requirePermission('email_branding.read'),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const branding = await prisma.clientBranding.findUnique({
        where: { clientId: req.params.clientId },
      });

      if (!branding) {
        // Return default branding if not customized
        const globalBranding = await prisma.emailBrandingSetting.findFirst();
        return res.json({
          success: true,
          data: globalBranding || null,
        });
      }

      res.json({
        success: true,
        data: branding,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * PATCH /admin/clients/:clientId/branding
 * Update branding for a specific client/app
 */
router.patch(
  '/clients/:clientId/branding',
  requirePermission('email_branding.update'),
  emailBrandingRateLimit,
  // Phase 2.6A fix: this route previously accepted an unvalidated req.body
  // spread directly into a Prisma upsert — now validated against the same
  // field set as the global branding schema (adds replyTo, rejects unknown
  // fields via zod's default strict-unknown-keys-stripped behavior).
  validateBody(clientBrandingUpdateSchema),
  async (req: AuthenticatedRequest, res, next) => {
    try {
      const client = await prisma.authClient.findUnique({
        where: { id: req.params.clientId },
      });

      if (!client) {
        throw new AppError('Client not found', 'NOT_FOUND', 404);
      }

      const branding = await prisma.clientBranding.upsert({
        where: { clientId: req.params.clientId },
        create: {
          clientId: req.params.clientId,
          ...req.body,
        },
        update: req.body,
      });

      // Phase 2.6A: this route previously had no audit trail at all — add
      // one, matching the pattern already used for global branding updates.
      await writeAuditLog({
        userId: req.user!.id,
        clientId: req.params.clientId,
        action: 'CLIENT_UPDATED',
        resource: 'client_branding',
        resourceId: branding.id,
        metadata: { fields: Object.keys(req.body) },
        req,
      });

      res.json({
        success: true,
        data: branding,
        message: 'Client branding updated successfully',
      });
    } catch (error) {
      next(error);
    }
  }
);

// Note: email delivery status, retry, and resend are now handled by the
// CommunicationDeliveryLog-based resend center — see
// modules/communication/communication.routes.ts (GET /delivery-logs,
// POST /delivery-logs/:id/retry, etc.) — not this module.

export default router;
