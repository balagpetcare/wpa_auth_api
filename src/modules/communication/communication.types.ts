import type {
  CommunicationChannel,
  CommunicationProviderEnvironment,
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
    // Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md)
    replyTo?: string | null;
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
  // Phase 2.6A: optional app/client scope, threaded through to
  // dispatchEmail/dispatchSms for app-aware routing rule resolution.
  // Callers that don't pass it keep falling through to system-default
  // (appId=null) routing rules unchanged.
  clientId?: string | null;
};

export type RoutingSelectionInput = {
  channel: CommunicationChannel;
  purpose: CommunicationPurpose;
  countryCode?: string | null;
  language?: OtpTemplateLanguage;
  // Phase 2.6A (docs/phase-2-6a-app-aware-communication-routing-ui.md):
  // app/client scope for routing rule resolution. Optional — omitting it
  // (or passing a value with no matching app-specific rule) falls through
  // to the system-wide default rule/provider pool exactly as before this
  // change, so existing callers that don't pass appId are unaffected.
  appId?: string | null;
  // Restricts eligible providers to a matching environment (or providers
  // with no rule-level restriction). Optional for the same backward-
  // compatibility reason as appId.
  environment?: CommunicationProviderEnvironment | null;
};

// Thrown by findCandidateProviders when the most specific matching routing
// rule has enabled=false — the channel is deliberately blocked for this
// app/country/purpose scope, and no fallback should be attempted.
export class ChannelDisabledError extends Error {
  constructor(public ruleId: string) {
    super('Channel is disabled for this app/country/purpose.');
    this.name = 'ChannelDisabledError';
  }
}
