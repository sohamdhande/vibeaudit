import { Page } from 'puppeteer';
import { DiscoveredEndpoint } from '../types';
import { redactHeaders } from '../utils/redact';
import { isPrivateIP } from '../utils/agent';
import { normalizePath } from '../utils/dedup';

const AUTH_COOKIE_PATTERN = /session|sess|sid|auth|jwt|token|connect\.sid/i;
export const harvestedIds = new Set<string>();
export const capturedIds: Record<string, string> = {};

export async function setupInterceptor(
  page: Page,
  onEndpointDiscovered: (ep: DiscoveredEndpoint) => void
): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];
  const seen = new Set<string>();
  let hasSessionCookie = false;

  // We removed the SSRF protection block here to allow local scanning of localhost and 127.0.0.1

  // Track when the browser acquires a session cookie and intercept redirects
  page.on('response', async (response) => {
    try {
      const setCookieHeaders = response.headers()['set-cookie'];
      const cookies = Array.isArray(setCookieHeaders)
        ? setCookieHeaders
        : setCookieHeaders ? [setCookieHeaders] : [];
      if (cookies.some(c => AUTH_COOKIE_PATTERN.test(c.split('=')[0] || '') || AUTH_COOKIE_PATTERN.test(c))) {
        hasSessionCookie = true;
      }
      
      // Prevent redirect rebinding SSRF protection removed for local scanning
    } catch {}
  });

  page.on('response', async (response) => {
    try {
      if (response.status() === 200 && response.headers()['content-type']?.includes('application/json')) {
        const text = await response.text();
        const json = JSON.parse(text);
        const parsedUrl = new URL(response.url());
        let basePath = parsedUrl.pathname;
        if (basePath.endsWith('/')) basePath = basePath.slice(0, -1);
        // Strip list suffixes so we inject into the base resource path
        basePath = basePath.replace(/\/(all|recent|list)$/i, '');
        const normPath = normalizePath(basePath);

        const extractIds = (obj: any) => {
          if (!obj || typeof obj !== 'object') return;
          if (Array.isArray(obj)) {
            if (obj.length > 0) extractIds(obj[0]);
            return;
          }
          for (const key of Object.keys(obj)) {
            if (/(?:^|_)(id|orderId|vehicleId|postId|userId)$/i.test(key) || /id$/i.test(key)) {
              if (typeof obj[key] === 'string' || typeof obj[key] === 'number') {
                const val = String(obj[key]);
                harvestedIds.add(val);
                
                if (normPath.includes(':id')) {
                  capturedIds[normPath] = val;
                } else {
                  capturedIds[`${normPath}/:id`] = val;
                  const parts = normPath.split('/');
                  parts.pop();
                  capturedIds[`${parts.join('/')}/:id`] = val;
                }
              }
            } else if (typeof obj[key] === 'object') {
              extractIds(obj[key]);
            }
          }
        };
        extractIds(json);
      }
    } catch {}
  });

  page.on('response', async (response) => {
    try {
      const request = response.request();
      const url = request.url();
      const method = request.method();

      // Only track API endpoints
      if (!url.includes('/api/')) return;
      // Skip preflight and navigation methods
      if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) return;
      // Skip Next.js internal API routes
      if (url.includes('/api/auth/session') || url.includes('/api/auth/csrf')) return;

      const parsedUrl = new URL(url);
      const key = `${method}:${parsedUrl.pathname}`;
      if (seen.has(key)) return;
      seen.add(key);

      const headers = request.headers();
      // Puppeteer's request.headers() doesn't include browser-managed cookies,
      // so we also check if the browser has acquired a session cookie at this point
      const isAuthenticated = !!(headers['authorization'] || headers['cookie'] || hasSessionCookie);

      let authMethod: 'cookie' | 'jwt' | 'unknown' = 'unknown';
      if (headers['authorization']?.toLowerCase().includes('bearer ')) {
        authMethod = 'jwt';
      } else if (headers['cookie'] || hasSessionCookie) {
        authMethod = 'cookie';
      }

      const ep: DiscoveredEndpoint = {
        method,
        url,
        path: parsedUrl.pathname,
        statusCode: response.status(),
        isAuthenticated,
        authMethod,
        requestHeaders: redactHeaders(headers),
        requestBody: request.postData(),
        timestamp: Date.now(),
      };

      endpoints.push(ep);
      onEndpointDiscovered(ep);
    } catch (_) {
      // Silently ignore errors from detached frames
    }
  });

  return endpoints;
}
