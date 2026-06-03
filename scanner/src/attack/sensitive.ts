import { SensitiveField } from '../types';

// Patterns that indicate sensitive/private data in response bodies
const SENSITIVE_PATTERNS: Array<{ pattern: RegExp; category: SensitiveField['category'] }> = [
  // PII - Personally Identifiable Information
  { pattern: /name|fullName|full_name|firstName|lastName|displayName/i, category: 'PII' },
  { pattern: /email|emailAddress|email_address/i, category: 'PII' },
  { pattern: /phone|phoneNumber|phone_number|mobile/i, category: 'PII' },
  { pattern: /address|streetAddress|street_address|city|state|zip/i, category: 'PII' },
  { pattern: /ssn|socialSecurity|social_security|national_id/i, category: 'PII' },
  { pattern: /dateOfBirth|date_of_birth|dob|birthDate|birth_date/i, category: 'PII' },

  // PHI - Protected Health Information
  { pattern: /diagnosis|condition|treatment|medication|prescription/i, category: 'PHI' },
  { pattern: /record|patient|medical|health|clinical/i, category: 'PHI' },
  { pattern: /allergy|allergies|immunization|vaccination/i, category: 'PHI' },
  { pattern: /bloodType|blood_type|labResult|lab_result/i, category: 'PHI' },
  { pattern: /notes|clinicalNotes|clinical_notes/i, category: 'PHI' },

  // Financial
  { pattern: /creditCard|credit_card|cardNumber|card_number/i, category: 'FINANCIAL' },
  { pattern: /bankAccount|bank_account|routing|iban/i, category: 'FINANCIAL' },
  { pattern: /salary|income|balance|payment/i, category: 'FINANCIAL' },

  // Auth tokens
  { pattern: /password|secret|token|apiKey|api_key|privateKey|private_key/i, category: 'AUTH' },
];

export function detectSensitiveFields(data: Record<string, any>): SensitiveField[] {
  const fields: SensitiveField[] = [];

  for (const [key, value] of Object.entries(data)) {
    // Skip internal/meta fields
    if (key === 'id' || key === '_id' || key === 'createdAt' || key === 'updatedAt') continue;

    let matched = false;
    for (const { pattern, category } of SENSITIVE_PATTERNS) {
      if (pattern.test(key)) {
        fields.push({ key, value, category });
        matched = true;
        break;
      }
    }

    // If not matched by key name but value looks like sensitive data
    if (!matched && typeof value === 'string') {
      // Check if value looks like an email
      if (/^[^@]+@[^@]+\.[^@]+$/.test(value)) {
        fields.push({ key, value, category: 'PII' });
      }
      // Check if value looks like a phone number
      else if (/^\+?[\d\s\-()]{7,}$/.test(value)) {
        fields.push({ key, value, category: 'PII' });
      }
      // Check if value looks like an SSN
      else if (/^\d{3}-\d{2}-\d{4}$/.test(value)) {
        fields.push({ key, value, category: 'PII' });
      }
    }
  }

  return fields;
}

export function formatSensitiveField(field: SensitiveField): string {
  const icon = {
    PII: '👤',
    PHI: '🏥',
    FINANCIAL: '💳',
    AUTH: '🔑',
    UNKNOWN: '⚠️',
  }[field.category];

  const truncated = typeof field.value === 'string' && field.value.length > 60
    ? field.value.slice(0, 57) + '...'
    : field.value;

  return `${icon} ${field.category} | ${field.key}: ${JSON.stringify(truncated)}`;
}
