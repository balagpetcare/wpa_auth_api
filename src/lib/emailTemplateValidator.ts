import { AppError } from './errors.js'

interface ValidationResult {
  valid: boolean
  errors: string[]
  warnings: string[]
}

export class EmailTemplateValidator {
  /**
   * Validate email template before save
   */
  static validate(template: {
    name: string
    subject: string
    htmlBody: string
    textBody?: string
    variables?: { required?: string[]; optional?: string[] }
  }): ValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    // Check required fields
    if (!template.name || template.name.trim().length === 0) {
      errors.push('Template name is required')
    }
    if (!template.subject || template.subject.trim().length === 0) {
      errors.push('Subject is required')
    }
    if (!template.htmlBody || template.htmlBody.trim().length === 0) {
      errors.push('HTML body is required')
    }

    // Check variable references in subject and body
    const usedVariables = this.extractVariables(template.subject + ' ' + template.htmlBody)
    const definedVariables = new Set([
      ...(template.variables?.required || []),
      ...(template.variables?.optional || []),
    ])

    // Check for undefined variables
    const undefinedVars = Array.from(usedVariables).filter((v) => !definedVariables.has(v))
    if (undefinedVars.length > 0) {
      errors.push(
        `Undefined variables used in template: ${undefinedVars.join(', ')}. Define them in the variables schema.`
      )
    }

    // Check for unsafe HTML patterns
    const unsafePatterns = [
      /<script[^>]*>[\s\S]*?<\/script>/gi,
      /on\w+\s*=/gi, // Event handlers
      /javascript:/gi,
      /vbscript:/gi,
      /eval\(/gi,
    ]

    for (const pattern of unsafePatterns) {
      if (pattern.test(template.htmlBody)) {
        errors.push('HTML contains unsafe patterns (scripts, event handlers, or unsafe protocols)')
        break
      }
    }

    // Check for invalid URLs
    const urlPattern = /href=["']([^"']+)["']|src=["']([^"']+)["']/gi
    let match
    while ((match = urlPattern.exec(template.htmlBody)) !== null) {
      const url = match[1] || match[2]
      if (!this.isValidUrl(url) && !this.isTemplateVariable(url)) {
        warnings.push(`Invalid or potentially unsafe URL found: ${url}`)
      }
    }

    // Check for missing CTA/link if there are link variables
    const hasLinkVariable = Array.from(usedVariables).some((v) =>
      v.match(/link|url|button|action/i)
    )
    if (hasLinkVariable && !/<a[^>]*href/.test(template.htmlBody)) {
      warnings.push('Template uses link variables but has no anchor tags. Ensure links are properly rendered.')
    }

    // Check plain text fallback
    if (!template.textBody || template.textBody.trim().length === 0) {
      warnings.push('Plain text body is empty. Email clients without HTML support may display poorly.')
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    }
  }

  /**
   * Extract {{variable}} references from template text
   */
  private static extractVariables(text: string): Set<string> {
    const variables = new Set<string>()
    const varPattern = /\{\{(\w+)\}\}/g
    let match
    while ((match = varPattern.exec(text)) !== null) {
      variables.add(match[1])
    }
    return variables
  }

  /**
   * Check if string is a template variable reference
   */
  private static isTemplateVariable(text: string): boolean {
    return /^\{\{[\w]+\}\}$/.test(text)
  }

  /**
   * Basic URL validation
   */
  private static isValidUrl(url: string): boolean {
    if (this.isTemplateVariable(url)) return true
    try {
      new URL(url)
      return true
    } catch {
      return false
    }
  }

  /**
   * Validate variables schema
   */
  static validateVariablesSchema(variables?: {
    required?: string[]
    optional?: string[]
  }): ValidationResult {
    const errors: string[] = []
    const warnings: string[] = []

    if (!variables) {
      return { valid: true, errors, warnings }
    }

    // Check for duplicate variables
    const required = variables.required || []
    const optional = variables.optional || []
    const allVariables = [...required, ...optional]
    const duplicates = allVariables.filter((v, i) => allVariables.indexOf(v) !== i)

    if (duplicates.length > 0) {
      errors.push(`Variables appear in both required and optional: ${duplicates.join(', ')}`)
    }

    // Check variable name format (should be alphanumeric and underscore)
    for (const variable of allVariables) {
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(variable)) {
        errors.push(
          `Invalid variable name: "${variable}". Variables must start with a letter or underscore and contain only alphanumeric characters and underscores.`
        )
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    }
  }
}
