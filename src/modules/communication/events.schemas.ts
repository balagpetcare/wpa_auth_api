import { z } from 'zod';

export const externalCommunicationEventNameSchema = z.enum([
  'VACCINATION_PAYMENT_CONFIRMED',
  'DONATION_PAYMENT_CONFIRMED',
  'MEMBERSHIP_PAYMENT_CONFIRMED',
]);

export const externalCommunicationChannelSchema = z.enum(['sms', 'email']);

function normalizeBangladeshPhone(input: string): string {
  const trimmed = input.trim();
  let cleaned = trimmed.replace(/[^\d+]/g, '');

  if (!cleaned.startsWith('+') && cleaned.startsWith('01') && cleaned.length === 11) {
    cleaned = `+88${cleaned}`;
  } else if (!cleaned.startsWith('+')) {
    cleaned = `+${cleaned}`;
  }

  if (!/^\+[1-9]\d{7,14}$/.test(cleaned)) {
    throw new Error('INVALID_PHONE');
  }

  return cleaned;
}

export const externalCommunicationEventSchema = z.object({
  event: externalCommunicationEventNameSchema,
  locale: z.string().min(2).max(12).default('bn'),
  channels: z.array(externalCommunicationChannelSchema).min(1).max(2).refine((items) => new Set(items).size === items.length, {
    message: 'channels must not contain duplicates.',
  }),
  recipient: z.object({
    name: z.string().min(1).max(120).optional(),
    phone: z.string().min(8).max(32).optional(),
    email: z.string().email().optional(),
  }).strict(),
  data: z.object({
    bookingRef: z.string().min(1).max(120),
    paymentRef: z.string().min(1).max(120),
    amount: z.coerce.number().finite().positive(),
    currency: z.string().min(3).max(12),
    campaignName: z.string().min(1).max(180),
    petCount: z.coerce.number().int().nonnegative().optional(),
    venueName: z.string().min(1).max(180).optional(),
    sessionDate: z.string().min(1).max(32).optional(),
    sessionTime: z.string().min(1).max(64).optional(),
    bookingSlipUrl: z.string().url().optional(),
    supportPhone: z.string().min(6).max(32).optional(),
  }).strict(),
}).strict().superRefine((value, ctx) => {
  if (value.channels.includes('sms')) {
    if (!value.recipient.phone) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'recipient.phone is required when sms is requested.', path: ['recipient', 'phone'] });
    } else {
      try {
        normalizeBangladeshPhone(value.recipient.phone);
      } catch {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'recipient.phone must be a valid phone number.', path: ['recipient', 'phone'] });
      }
    }
  }

  if (value.channels.includes('email') && !value.recipient.email) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'recipient.email is required when email is requested.', path: ['recipient', 'email'] });
  }

  if (value.event === 'VACCINATION_PAYMENT_CONFIRMED' && !value.data.bookingSlipUrl) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'data.bookingSlipUrl is required for VACCINATION_PAYMENT_CONFIRMED.',
      path: ['data', 'bookingSlipUrl'],
    });
  }
});

export type ExternalCommunicationEventInput = z.infer<typeof externalCommunicationEventSchema>;

export function normalizeEventPhone(phone: string): string {
  return normalizeBangladeshPhone(phone);
}
