import { Page } from 'puppeteer';
import { DiscoveredEndpoint } from '../types';
import { redactHeaders } from '../utils/redact';
import { promises as dns } from 'dns';

const AUTH_COOKIE_PATTERN = /session|sess|sid|auth|jwt|token|connect\.sid/i;
import { isPrivateIP } from '../utils/agent';
export async function setupInterceptor(
  page: Page,
  onEndpointDiscovered: (ep: DiscoveredEndpoint) => void
): Promise<DiscoveredEndpoint[]> {
  const endpoints: DiscoveredEndpoint[] = [];
  const seen = new Set<string>();
  let hasSessionCookie = false;

  // SSRF Protection: Intercept and block requests to private/internal IPs
  await page.setRequestInterception(true);

  page.on('request', async (request) => {
    try {
      if (request.isInterceptResolutionHandled()) return;
      const url = request.url();
      
      // Allow data URIs
      if (url.startsWith('data:')) {
        await request.continue();
        return;
      }

      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase();
      
      const blockedHostnames = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '169.254.169.254'];

      if (blockedHostnames.includes(hostname)) {
        await request.abort('accessdenied');
        return;
      }
      
      try {
        const lookupResult = await dns.lookup(hostname);
        if (isPrivateIP(lookupResult.address)) {
          await request.abort('accessdenied');
          return;
        }
      } catch (err) {
        await request.abort('namenotresolved');
        return;
      }

      await request.continue();
    } catch (_) {
      if (!request.isInterceptResolutionHandled()) {
        await request.continue().catch(() => {});
      }
    }
  });

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
      
      // Prevent redirect rebinding
      const status = response.status();
      if (status >= 300 && status < 400) {
        const location = response.headers()['location'];
        if (location) {
          const redirectUrl = new URL(location, response.url());
          const redirectHostname = redirectUrl.hostname.toLowerCase();
          const lookupResult = await dns.lookup(redirectHostname);
          if (isPrivateIP(lookupResult.address)) {
            console.error(`[CRAWLER] Blocked SSRF via redirect to ${location}`);
            await page.close(); // Close the page forcefully to stop the redirect chain
          }
        }
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
