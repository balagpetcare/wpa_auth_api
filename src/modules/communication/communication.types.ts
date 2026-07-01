import type {
  CommunicationChannel,
  CommunicationPurpose,
  OtpTemplateLanguage,
  OtpTemplatePurpose,
} from '@prisma/client';

export type ProviderCredentialSecrets = Record<string, string>;

export type SmsSendInput = {
  to: string;
  message: string;
  countryCode?: string | null;
  provider: {
    id: string;
    name: string;
    code: string;
  };
  credentials: ProviderCredentialSecrets;
  metadata?: Record<string, unknown>;
};

export type EmailSendInput = {
  to: string;
  subject: string;
  text?: string;
  html?: string;
  provider: {
    id: string;
    name: string;
    code: string;
  };
  credentials: ProviderCredentialSecrets;
  config: {
    fromEmail?: string | null;
    fromName?: string | null;
    smtpHost?: string | null;
    smtpPort?: number | null;
    smtpSecure?: boolean | null;
  };
  metadata?: Record<string, unknown>;
};

export type ProviderSendResult = {
  success: boolean;
  providerMessageId?: string | null;
  rawResponse?: Record<string, unknown> | null;
  errorCode?: string | null;
  errorMessage?: string | null;
};

export type OtpCommunicationInput = {
  purpose: OtpTemplatePurpose;
  language?: OtpTemplateLanguage;
  otp: string;
  minutes?: number;
  phone?: string | null;
  email?: string | null;
  userId?: string | null;
};

export type RoutingSelectionInput = {
  channel: CommunicationChannel;
  purpose: CommunicationPurpose;
  countryCode?: string | null;
  language?: OtpTemplateLanguage;
};
