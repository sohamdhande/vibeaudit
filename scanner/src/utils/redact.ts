export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const redacted = { ...headers };
  const sensitiveKeys = ['authorization', 'cookie', 'set-cookie', 'x-api-key', 'proxy-authorization'];
  for (const key of Object.keys(redacted)) {
    if (sensitiveKeys.includes(key.toLowerCase())) {
      redacted[key] = '[REDACTED]';
    }
  }
  return redacted;
}

export function summarizeForPrompt(data: unknown): any {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') {
    return data.length > 20 ? `[REDACTED:${data.length} chars]` : data;
  }
  if (typeof data === 'number') {
    return '[NUMBER]';
  }
  if (Array.isArray(data)) {
    return data.map(item => typeof item === 'object' && item !== null ? `{ ${Object.keys(item).length} keys }` : summarizeForPrompt(item));
  }
  if (typeof data === 'object') {
    const summarized: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        summarized[key] = `{ ${Object.keys(value).length} keys }`;
      } else {
        summarized[key] = summarizeForPrompt(value);
      }
    }
    return summarized;
  }
  return data;
}

export function escapeMarkdown(s: string): string {
  if (!s) return s;
  return s.replace(/([\\*_[\]()#!|`])/g, '\\$1');
}
