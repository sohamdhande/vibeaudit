import axios from 'axios';
import puppeteer from 'puppeteer';
import { BOLAFinding, DiscoveredEndpoint, ScanConfig, UserCredentials } from '../types';
import { detectAndLogin, LoginFailedError } from '../crawler/crawler';
import { detectSensitiveFields } from './sensitive';
import { safeHttpAgent, safeHttpsAgent } from '../utils/agent';
import { analyzeVulnerability } from '../ai/patch';

function extractResourceId(data: any): any {
  if (!data || typeof data !== 'object') return null;
  const idFields = ['id', '_id', 'userId', 'recordId', 'resourceId', 'uuid'];
  for (const field of idFields) {
    if (Object.prototype.hasOwnProperty.call(data, field) && data[field] != null) {
      return data[field];
    }
  }
  return null;
}

function isResourceIdShaped(value: string): boolean {
  if (!value) return false;
  if (/^\d+$/.test(value)) return true;
  if (/^[0-9a-f-]{36}$/i.test(value)) return true;
  if (/^[A-Z0-9_-]{4,64}$/i.test(value)) return true;
  return false;
}

async function getPuppeteerSession(
  targetUrl: string,
  creds: UserCredentials,
  config: ScanConfig,
  label: string,
  signal?: AbortSignal
): Promise<string> {
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const loginPath = config.loginPath || '/login';
  
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'],
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    let timeoutId: NodeJS.Timeout;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => reject(new LoginFailedError(`Puppeteer session fetch timed out after 15s for ${label}`)), 15000);
    });

    const sessionPromise = (async () => {
      if (signal?.aborted) throw new Error('Scan aborted');
      await page.goto(`${baseUrl}${loginPath}`, { waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
      if (signal?.aborted) throw new Error('Scan aborted');
      await new Promise(r => setTimeout(r, 1000));
      
      await detectAndLogin(page, creds, (msg) => console.log(`[ATTACK:${label}] ${msg}`));
      await new Promise(r => setTimeout(r, 2000));
      if (signal?.aborted) throw new Error('Scan aborted');
      
      const cookies = await page.cookies();
      if (cookies.length === 0) {
         throw new LoginFailedError(`No cookies found after login for ${label}`);
      }
      const allCookies = cookies.map(c => `${c.name}=${c.value}`).join('; ');
      return allCookies;
    })();

    return await Promise.race([sessionPromise, timeoutPromise]).finally(() => clearTimeout(timeoutId));
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

async function getJWTToken(
  targetUrl: string,
  creds: UserCredentials,
  loginPath: string,
  label: string,
  signal?: AbortSignal
): Promise<string> {
  if (signal?.aborted) throw new Error('Scan aborted');
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const endpointsToTry = [
    loginPath,
    '/api/auth/login',
    '/api/login',
    '/api/auth/signin',
    '/auth/login'
  ];

  for (const endpoint of endpointsToTry) {
    if (!endpoint) continue;
    try {
      console.log(`[ATTACK:${label}] Trying JWT login at ${endpoint}...`);
      const res = await axios.post(`${baseUrl}${endpoint}`, {
        email: creds.email,
        password: creds.password,
      }, { 
        validateStatus: () => true,
        httpAgent: safeHttpAgent,
        httpsAgent: safeHttpsAgent,
        signal,
      });

      if (res.status === 200) {
        const data = res.data;
        const token = data?.token || data?.accessToken || data?.access_token || data?.jwt || res.headers['authorization']?.replace(/Bearer /i, '');
        if (token) {
          console.log(`[ATTACK:${label}] JWT token obtained from ${endpoint}`);
          return token;
        }
      }
    } catch (e) {}
  }
  
  throw new Error(`Failed to obtain JWT token for ${label} across known endpoints.`);
}

const SAFE_HEADERS = ['accept', 'accept-language', 'content-type', 'x-tenant-id', 'x-api-version', 'x-csrf-token', 'x-requested-with'];

function forwardSafeHeaders(originalHeaders: Record<string, string>): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const [k, v] of Object.entries(originalHeaders)) {
    if (SAFE_HEADERS.includes(k.toLowerCase())) {
      safe[k] = v;
    }
  }
  return safe;
}

async function fetchResource(
  url: string,
  authType: 'cookie' | 'jwt' | 'unknown',
  token: string,
  originalHeaders: Record<string, string> = {},
  signal?: AbortSignal
): Promise<{ status: number; data: any }> {
  try {
    const headers: any = { ...forwardSafeHeaders(originalHeaders) };
    if (token) {
      if (authType === 'jwt') {
        headers['Authorization'] = `Bearer ${token}`;
      } else {
        headers['Cookie'] = token;
      }
    }
    const res = await axios.get(url, {
      headers,
      validateStatus: () => true,
      timeout: 10000,
      httpAgent: safeHttpAgent,
      httpsAgent: safeHttpsAgent,
      signal,
    });
    return { status: res.status, data: res.data };
  } catch (err: unknown) {
    return { status: 0, data: null };
  }
}

/**
 * Score a candidate endpoint for BOLA testing priority.
 * Higher score = more likely to be a vulnerable parameterized resource.
 */
function scoreCandidateEndpoint(ep: DiscoveredEndpoint): number {
  let score = 0;
  
  // Prefer deeper parameterized paths (e.g., /api/records/REC-123 over /api/health)
  const segments = ep.path.split('/').filter(Boolean);
  if (segments.length >= 3) score += 2;
  
  // Prefer endpoints whose last segment looks like a resource ID
  const lastSegment = segments[segments.length - 1] || '';
  if (/^[A-Z]+-\d+$/.test(lastSegment)) score += 3;          // PREFIX-ID pattern
  if (/^[0-9a-f-]{36}$/.test(lastSegment)) score += 3;       // UUID pattern
  if (/^\d+$/.test(lastSegment)) score += 2;                  // Numeric ID
  
  // Prefer authenticated endpoints
  if (ep.isAuthenticated) score += 1;
  
  return score;
}

function calculateConfidence(finding: {
  sensitiveFields?: { key: string }[];
  attackerAuthenticated: boolean;
  stolenData?: any;
}): number {
  let score = 40; // base: authenticated 200 response

  // PII/sensitive fields found
  const fieldCount = finding.sensitiveFields?.length || 0;
  score += Math.min(fieldCount * 8, 40); // max +40

  // Response size match (attacker got same data as victim)
  const responseStr = JSON.stringify(finding.stolenData || {});
  if (responseStr.length > 100) score += 10;

  // Unauthenticated access is worse
  if (!finding.attackerAuthenticated) score += 10;

  return Math.min(score, 100);
}

export async function runBOLAAttack(
  config: ScanConfig,
  endpoints: DiscoveredEndpoint[],
  authType: 'cookie' | 'jwt' | 'unknown',
  emit: (...args: any[]) => void,
  signal?: AbortSignal
): Promise<import('../types').BOLAResult> {
  const targetUrl = config.targetUrl.replace(/\/+$/, '');

  // Find parameterized GET endpoints (e.g., /api/records/REC-xxxxx, /api/users/123)
  // Don't require isAuthenticated — the interceptor can't see browser-managed cookies
  const candidates = endpoints.filter((ep) => {
    if (ep.statusCode >= 400) return false;
    
    // Check path segments
    const segments = ep.path.split('/').filter(Boolean);
    if (segments.some(seg => isResourceIdShaped(seg))) return true;
    
    // Check query params
    try {
      const url = new URL(ep.url);
      for (const [_, val] of url.searchParams.entries()) {
        if (isResourceIdShaped(val)) return true;
      }
    } catch {}
    
    // Check request body
    if (ep.requestBody) {
      try {
        const body = JSON.parse(ep.requestBody);
        if (typeof body === 'object' && body !== null) {
          for (const val of Object.values(body)) {
            if (typeof val === 'string' && isResourceIdShaped(val)) return true;
            if (typeof val === 'number') return true;
          }
        }
      } catch {}
    }
    
    return false;
  });

  if (candidates.length === 0) {
    emit('[ATTACK] No parameterized endpoints discovered during crawl.');
    emit('⚠️ No parameterized API endpoints discovered. Try adding more pages to pagesToCrawl.');
    return { finding: null, reason: 'no_candidates' };
  }

  // Sort candidates by score — best targets first
  candidates.sort((a, b) => scoreCandidateEndpoint(b) - scoreCandidateEndpoint(a));

  emit(`[ATTACK] Found ${candidates.length} candidate endpoint(s): ${candidates.map(c => c.path).join(', ')}`);
  emit('[ATTACK] Initiating BOLA verification...');

  // Authenticate User A (victim) using config credentials
  let victimToken: string;
  try {
    emit(`[ATTACK] Establishing User A session (${config.userA.email})...`);
    if (authType === 'jwt') {
      emit('[ATTACK] Fetching JWT token for victim session...');
      victimToken = await getJWTToken(targetUrl, config.userA, config.loginPath || '', 'UserA', signal);
    } else {
      emit('[ATTACK] Opening browser session for victim...');
      victimToken = await getPuppeteerSession(targetUrl, config.userA, config, 'UserA', signal);
    }
    emit('[ATTACK] User A authenticated ✓');
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    emit(`[ATTACK] Failed to authenticate User A: ${errorMessage}`);
    return { finding: null, reason: 'not_exploitable' };
  }

  // Authenticate User B (attacker) — if the account doesn't exist, use unauthenticated access
  let attackerToken: string = '';
  let attackerAuthenticated = false;
  let attackerType: 'authenticated_attacker' | 'unauthenticated_probe' = 'unauthenticated_probe';
  try {
    emit(`[ATTACK] Establishing User B session (${config.userB.email})...`);
    if (authType === 'jwt') {
      emit('[ATTACK] Fetching JWT token for attacker session...');
      attackerToken = await getJWTToken(targetUrl, config.userB, config.loginPath || '', 'UserB', signal);
    } else {
      emit('[ATTACK] Opening browser session for attacker...');
      attackerToken = await getPuppeteerSession(targetUrl, config.userB, config, 'UserB', signal);
    }
    attackerAuthenticated = true;
    attackerType = 'authenticated_attacker';
    emit('[ATTACK] User B authenticated ✓');
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    emit(`[ATTACK] User B auth failed: ${errorMessage}`);
    emit('[ATTACK] Continuing with unauthenticated probe for public object exposure...');
    attackerToken = '';
    attackerAuthenticated = false;
    attackerType = 'unauthenticated_probe';
  }

  let any401or403 = false;
  let anyNoSensitiveData = false;
  let anyInconclusive = false;

  emit('warning', 'csrf_limitation', 
    'CSRF tokens are not replayed. Endpoints using CSRF protection ' +
    'may produce false negatives. Manual verification recommended.');

  let completed = 0;
  const total = candidates.length;

  for (const endpoint of candidates) {
    if (signal?.aborted) throw new Error('Scan aborted');
    const resourceUrl = `${targetUrl}${endpoint.path}`;

    // Progress: BEFORE testing
    emit('attack', 'testing', `Testing ${endpoint.method} ${endpoint.path}`, {
      endpoint: endpoint.path, method: endpoint.method, completed, total
    });

    emit(`[ATTACK] Testing endpoint: ${endpoint.method} ${endpoint.path}`);
    emit(`[ATTACK] Fetching resource as User A (owner)...`);
    const victimRes = await fetchResource(resourceUrl, authType, victimToken, endpoint.requestHeaders, signal);

    if (victimRes.status !== 200) {
      emit(`[ATTACK] User A got ${victimRes.status}, skipping...`);
      completed++;
      emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — skipped (${victimRes.status})`, {
        endpoint: endpoint.path, method: endpoint.method, completed, total
      });
      continue;
    }

    const userAResourceId = extractResourceId(victimRes.data);

    emit(`[ATTACK] User A → ${victimRes.status} OK (resource exists)`);
    
    if (attackerToken) {
      emit('[ATTACK] Switching to User B session...');
      if (authType === 'jwt') {
        emit('[ATTACK] Replaying request with attacker Bearer token...');
      } else {
        emit(`[ATTACK] Replaying same request as User B (non-owner)...`);
      }
    } else {
      emit('[ATTACK] Replaying same request with NO authentication...');
    }

    const attackerRes = await fetchResource(resourceUrl, authType, attackerToken, endpoint.requestHeaders, signal);

    if (attackerRes.status === 200 && attackerRes.data && typeof attackerRes.data === 'object') {
      const responseStr = JSON.stringify(attackerRes.data);
      const denialPattern = /access.?denied|unauthorized|forbidden|not.?allowed|permission.?denied|you.?don.?t.?have/i;
      
      if (denialPattern.test(responseStr)) {
        emit(`[ATTACK] User B got 200 OK but response contained denial text. Protected.`);
        any401or403 = true;
        completed++;
        emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — protected`, {
          endpoint: endpoint.path, method: endpoint.method, completed, total
        });
        continue;
      }

      if (responseStr.length < 50) {
        emit(`[ATTACK] User B got 200 OK but response was suspiciously short. Inconclusive.`);
        anyInconclusive = true;
        completed++;
        emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — inconclusive`, {
          endpoint: endpoint.path, method: endpoint.method, completed, total
        });
        continue;
      }

      const userBData = attackerRes.data;
      // Explicit identity/resource matching. Do not default to true!
      const containsUserAResource = userAResourceId != null ? JSON.stringify(userBData).includes(String(userAResourceId)) : false;

      // If no explicit ID match, do structural response diffing to verify it's the exact same data
      let dataMatch = containsUserAResource;
      if (!dataMatch) {
        // If attacker gets the EXACT same data length/structure as victim, it's likely a BOLA
        const victimDataStr = JSON.stringify(victimRes.data);
        const attackerDataStr = JSON.stringify(userBData);
        if (victimDataStr === attackerDataStr && victimDataStr.length > 50) {
          dataMatch = true;
        }
      }

      if (!dataMatch) {
        emit(`[ATTACK] Data does not belong to User A, skipping false positive...`);
        completed++;
        emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — no data match`, {
          endpoint: endpoint.path, method: endpoint.method, completed, total
        });
        continue;
      }

      // Detect sensitive fields in the stolen data
      const sensitiveFields = detectSensitiveFields(attackerRes.data);
      const victimSensitiveFields = detectSensitiveFields(victimRes.data);

      const hasVictimData = victimSensitiveFields.some(vf => 
        JSON.stringify(attackerRes.data).includes(String(vf.value))
      );

      if (!hasVictimData) {
        emit(`[ATTACK] False positive detected: Attacker response does not contain victim's sensitive data.`);
        completed++;
        emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — false positive filtered`, {
          endpoint: endpoint.path, method: endpoint.method, completed, total
        });
        continue;
      }

      if (sensitiveFields.length > 0) {
        emit(`[ATTACK] ${attackerToken ? 'User B' : 'Unauthenticated'} → ${attackerRes.status} OK`);

        const partialFinding = {
          sensitiveFields,
          attackerAuthenticated,
          stolenData: attackerRes.data,
        };
        const confidenceScore = calculateConfidence(partialFinding);

        const exploitType = attackerType === 'unauthenticated_probe' ? 'unauthenticated_access' : 'bola';
        emit(attackerType === 'unauthenticated_probe'
          ? '[EXPLOIT CONFIRMED] Unauthenticated data access successful'
          : '[EXPLOIT CONFIRMED] Cross-user data access successful', {
          endpoint: endpoint.path,
          exploitType,
          confidenceScore,
          stolenData: attackerRes.data
        });

        emit(attackerType === 'unauthenticated_probe'
          ? '🚨 Unauthenticated access vulnerability confirmed.'
          : '🚨 BOLA vulnerability confirmed.');
        emit(`[ATTACK] Exploit confidence: ${confidenceScore}%`);

        // AI-driven CVSS analysis
        emit('[ATTACK] Running AI vulnerability analysis for CVSS scoring...');
        const victimResponseStr = JSON.stringify(victimRes.data);
        const attackerResponseStr = JSON.stringify(attackerRes.data);
        const analysis = await analyzeVulnerability(endpoint.path, victimResponseStr, attackerResponseStr);
        emit(`[ATTACK] AI CVSS Score: ${analysis.cvssScore} (${analysis.severity})`);
        emit(`[ATTACK] Data exposed: ${analysis.dataExposed.join(', ')}`);
        
        const curlReproduction = attackerToken
          ? (authType === 'jwt' ? `curl -H "Authorization: Bearer ATTACKER_TOKEN" ${resourceUrl}` : `curl -H "Cookie: SESSION_TOKEN=ATTACKER_TOKEN" ${resourceUrl}`)
          : `curl ${resourceUrl}`;

        completed++;
        emit('attack', 'vulnerable', `${endpoint.method} ${endpoint.path} — VULNERABLE`, {
          endpoint: endpoint.path, method: endpoint.method, completed, total
        });

        return {
          finding: {
            endpoint: endpoint.path,
            method: endpoint.method,
            victimToken,
            attackerToken: attackerToken || 'NONE (unauthenticated)',
            victimResourceId: endpoint.path.split('/').pop() || '',
            stolenData: attackerRes.data,
            sensitiveFields,
            attackerAuthenticated,
            curlReproduction,
            cvssScore: analysis.cvssScore,
            severity: analysis.severity,
            confidenceScore: analysis.confidence > 0 ? analysis.confidence : confidenceScore,
            dataExposed: analysis.dataExposed,
            exploitType,
          } as BOLAFinding & { exploitType: 'bola' | 'unauthenticated_access' },
          reason: 'vulnerable'
        };
      } else {
        anyNoSensitiveData = true;
        emit(`[ATTACK] ${attackerToken ? 'User B' : 'Unauthenticated'} → ${attackerRes.status} OK but no sensitive data detected.`);
        completed++;
        emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — no sensitive data`, {
          endpoint: endpoint.path, method: endpoint.method, completed, total
        });
      }
    } else {
      if (attackerRes.status === 401 || attackerRes.status === 403) {
        any401or403 = true;
        emit(`[ATTACK] ${attackerToken ? 'User B' : 'Unauthenticated'} → ${attackerRes.status} Authorization checks in place`);
      } else if (attackerRes.status === 0 || attackerRes.status >= 500) {
        anyInconclusive = true;
        emit(`[ATTACK] ${attackerToken ? 'User B' : 'Unauthenticated'} → ${attackerRes.status} Network or server error — inconclusive`);
      } else if (attackerRes.status === 404) {
        anyInconclusive = true;
        emit(`[ATTACK] ${attackerToken ? 'User B' : 'Unauthenticated'} → ${attackerRes.status} Endpoint not found — inconclusive`);
      } else {
        anyInconclusive = true;
        emit(`[ATTACK] ${attackerToken ? 'User B' : 'Unauthenticated'} → ${attackerRes.status} Unexpected response — inconclusive`);
      }
      completed++;
      emit('attack', 'safe', `${endpoint.method} ${endpoint.path} — ${attackerRes.status}`, {
        endpoint: endpoint.path, method: endpoint.method, completed, total
      });
    }
  }

  emit('[ATTACK] No BOLA vulnerability confirmed on tested endpoints.');
  
  if (anyInconclusive) {
    emit('⚠️ Some endpoints returned network, server, or missing-route errors. Result is inconclusive.');
    return { finding: null, reason: 'inconclusive' };
  } else if (anyNoSensitiveData) {
    emit('✅ Endpoints found but no sensitive data exposed. App may be partially protected.');
    return { finding: null, reason: 'blocked' };
  } else if (any401or403) {
    emit('✅ Authorization checks appear to be in place. All endpoints returned 401/403 for attacker session.');
    return { finding: null, reason: 'not_exploitable' };
  }

  emit('⚠️ No attacker responses were conclusive.');
  return { finding: null, reason: 'not_exploitable' };
}
