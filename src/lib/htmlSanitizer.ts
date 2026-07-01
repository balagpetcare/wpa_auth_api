/**
 * HTML Sanitizer
 * Sanitizes HTML for safe email rendering
 */

const DANGEROUS_TAGS = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button'];
const DANGEROUS_ATTRIBUTES = ['onclick', 'onload', 'onerror', 'onmouseover', 'javascript:'];

interface SanitizeOptions {
  allowedTags?: string[];
  allowedAttributes?: string[];
  stripScripts?: boolean;
}

/**
 * Sanitizes HTML content to prevent XSS attacks
 * Removes script tags and dangerous attributes
 */
export function sanitizeHtml(html: string, options: SanitizeOptions = {}): string {
  if (!html || typeof html !== 'string') {
    return '';
  }

  let result = html;

  // Remove script tags and content
  result = result.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

  // Remove event handlers
  result = result.replace(/\s*on\w+\s*=\s*"[^"]*"/gi, '');
  result = result.replace(/\s*on\w+\s*=\s*'[^']*'/gi, '');
  result = result.replace(/\s*on\w+\s*=\s*[^\s>]*/gi, '');

  // Remove javascript: protocol
  result = result.replace(/javascript:/gi, '');

  // Remove dangerous tags
  for (const tag of DANGEROUS_TAGS) {
    const regex = new RegExp(`<${tag}\\b[^<]*(?:(?!<\\/${tag}>)<[^<]*)*<\\/${tag}>`, 'gi');
    result = result.replace(regex, '');
  }

  return result.trim();
}

/**
 * Validates a URL is safe to use in email
 * Only allows http/https protocols
 */
export function isValidEmailUrl(url: string | null | undefined): boolean {
  if (!url || typeof url !== 'string') {
    return false;
  }

  try {
    const urlObj = new URL(url);
    // Only allow http and https
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Escapes special HTML characters
 */
export function escapeHtml(text: string | null | undefined): string {
  if (!text || typeof text !== 'string') {
    return '';
  }

  const htmlEscapeMap: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };

  return text.replace(/[&<>"']/g, (char) => htmlEscapeMap[char] || char);
}

/**
 * Escapes text for safe use in HTML attributes
 */
export function escapeAttribute(text: string | null | undefined): string {
  if (!text || typeof text !== 'string') {
    return '';
  }

  return text
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
