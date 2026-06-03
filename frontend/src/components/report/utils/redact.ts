import type { SensitiveField } from '@/types';

/**
 * Redact tokens from curl reproduction strings.
 * Replaces Cookie, Authorization, and X-Auth-Token header values.
 */
export function redactCurl(curl: string): string {
  if (!curl) return '';
  return curl.replace(
    /(Cookie|Authorization|X-Auth-Token):\s*\S+/gi,
    '$1: [REDACTED]'
  );
}

/**
 * Format a sensitive field for display — show key and category only, never the value.
 */
export function redactFieldValue(field: SensitiveField): string {
  return `${field.key} (${field.category})`;
}

/**
 * Get severity label for a sensitive field category.
 */
export function getCategorySeverity(category: string): string {
  switch (category) {
    case 'PII': return 'High';
    case 'PHI': return 'Critical';
    case 'FINANCIAL': return 'Critical';
    case 'AUTH': return 'Critical';
    default: return 'Medium';
  }
}

/**
 * Format a timestamp as a human-readable date string for reports.
 */
export function formatReportDate(ts: number): string {
  return new Date(ts).toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/**
 * Format duration in milliseconds to human-readable string.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds}s`;
}

/**
 * Get severity label from confidence score.
 */
export function getSeverityLabel(confidenceScore: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  if (confidenceScore >= 90) return 'CRITICAL';
  if (confidenceScore >= 70) return 'HIGH';
  if (confidenceScore >= 50) return 'MEDIUM';
  return 'LOW';
}

/**
 * Get the display color for a severity level.
 */
export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '#c0392b';
    case 'HIGH': return '#e67e22';
    case 'MEDIUM': return '#f1c40f';
    case 'LOW': return '#3498db';
    default: return '#555555';
  }
}

/**
 * Generate CVSS v3.1 vector string based on finding characteristics.
 */
export function getCvssVector(cvssScore: number, attackerAuthenticated: boolean): string {
  const pr = attackerAuthenticated ? 'L' : 'N';
  if (cvssScore >= 9.0) return `CVSS:3.1/AV:N/AC:L/PR:${pr}/UI:N/S:U/C:H/I:H/A:N`;
  if (cvssScore >= 7.0) return `CVSS:3.1/AV:N/AC:L/PR:${pr}/UI:N/S:U/C:H/I:N/A:N`;
  if (cvssScore >= 4.0) return `CVSS:3.1/AV:N/AC:L/PR:${pr}/UI:N/S:U/C:L/I:N/A:N`;
  return `CVSS:3.1/AV:N/AC:H/PR:${pr}/UI:N/S:U/C:L/I:N/A:N`;
}

/**
 * Get attack complexity rating from CVSS score.
 */
export function getAttackComplexity(cvssScore: number): string {
  if (cvssScore >= 8.0) return 'Low — no special conditions required';
  if (cvssScore >= 5.0) return 'Low — standard authentication sufficient';
  return 'Medium — specific conditions may apply';
}

/**
 * Derive applicable regulatory frameworks from sensitive field categories.
 */
export function getRegulatoryImpact(categories: string[]): string[] {
  const unique = new Set(categories);
  const regulations: string[] = [];

  if (unique.has('PII')) regulations.push('GDPR Art. 33 — Breach Notification');
  if (unique.has('PHI')) regulations.push('HIPAA § 164.404 — Breach Notification');
  if (unique.has('FINANCIAL')) regulations.push('PCI-DSS Req. 6.5 — Secure Coding');
  if (unique.has('AUTH')) regulations.push('SOC 2 CC6.1 — Logical Access');

  // Always include SOC2 if any sensitive data is exposed
  if (regulations.length > 0 && !unique.has('AUTH')) {
    regulations.push('SOC 2 CC6.1 — Logical Access');
  }

  return regulations;
}
