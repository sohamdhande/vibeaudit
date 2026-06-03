import { DiscoveredEndpoint } from '../types';

/**
 * Regex patterns for path segments that look like dynamic IDs.
 * Each matched segment is replaced with `:id` for normalization.
 */
const ID_PATTERNS = [
  /^[0-9]+$/,                                             // Pure numeric: 1, 42, 10023
  /^[0-9a-f]{24}$/i,                                      // MongoDB ObjectId: 507f1f77bcf86cd799439011
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID v1–v5
  /^cmp[a-z0-9]{10,}$/i,                                  // CUID-style: cmpk8f2hn0003jbvh0q62ocdc
  /^c[a-z0-9]{24,}$/i,                                    // CUID2 / long prefixed tokens
  /^[a-z0-9_-]{20,}$/i,                                   // Generic long opaque tokens (20+ chars)
];

/**
 * Returns true if a path segment looks like a dynamic resource ID
 * rather than a static route name.
 */
function isIdSegment(segment: string): boolean {
  return ID_PATTERNS.some((pattern) => pattern.test(segment));
}

/**
 * Normalize a URL path by replacing ID-like segments with `:id`.
 *
 * Examples:
 *   /api/orders/1001           → /api/orders/:id
 *   /api/orders/507f1f77bcf86cd799439011 → /api/orders/:id
 *   /api/v1/users/abc-def-123  → /api/v1/users/:id  (if UUID-shaped)
 *   /api/profile               → /api/profile        (no change)
 */
export function normalizePath(path: string): string {
  return path
    .split('/')
    .map((segment) => (segment && isIdSegment(segment) ? ':id' : segment))
    .join('/');
}

/**
 * Deduplicate discovered endpoints by METHOD + normalized path pattern.
 *
 * When multiple endpoints share the same HTTP method and normalized path
 * (e.g. GET /api/orders/1 and GET /api/orders/2 both normalize to
 * GET /api/orders/:id), only the first encountered representative is kept.
 *
 * This prevents the attack engine from wasting time testing the same
 * route handler with dozens of different resource IDs.
 */
export function deduplicateEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const seen = new Map<string, DiscoveredEndpoint>();

  for (const ep of endpoints) {
    const normalized = normalizePath(ep.path);
    const key = `${ep.method.toUpperCase()} ${normalized}`;

    if (!seen.has(key)) {
      seen.set(key, ep);
    }
  }

  return Array.from(seen.values());
}
