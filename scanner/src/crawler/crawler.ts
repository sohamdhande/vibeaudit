import puppeteer, { Page } from 'puppeteer';
import { setupInterceptor, harvestedIds, capturedIds } from './interceptor';
import { DiscoveredEndpoint, ScanConfig, UserCredentials } from '../types';
import { deduplicateEndpoints, normalizePath } from '../utils/dedup';

// Generic regex to detect parameterized resource links in the DOM
const PARAMETERIZED_LINK_PATTERN = /\/[a-zA-Z0-9_-]+\/([a-z0-9_-]{4,}|\d+|[A-Z]+-\d+)$/;

// Additional selectors to find resource links that the regex might miss
const RESOURCE_LINK_SELECTORS = [
  'a[href*="/api/"]',
  'a[href*="/orders/"]',
  'a[href*="/records/"]',
  'a[href*="/users/"]',
  'a[href*="/profile/"]',
  'a[href*="/item/"]',
  'a[href*="/product/"]',
];

// Common API paths to force-fetch for discovery
const COMMON_API_PATHS = [
  '/api/orders',
  '/api/records',
  '/api/users',
  '/api/profile',
  '/api/products',
];

// Timeout wrapper for promises
const withTimeout = <T>(promise: Promise<T>, ms: number, label: string): Promise<T> => {
  let timeoutId: NodeJS.Timeout;
  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`Timeout after ${ms}ms at: ${label}`));
    }, ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timeoutId));
};

export class LoginFailedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LoginFailedError';
  }
}

/**
 * Try a list of selectors against the page and return the first one that matches.
 * Never builds selectors from className strings — uses only attribute-based selectors.
 */
async function trySelectors(page: Page, selectors: string[]): Promise<string | null> {
  for (const sel of selectors) {
    try {
      const el = await page.$(sel);
      if (el) return sel;
    } catch (_) {
      // Some selectors (e.g. :has-text) may throw in certain contexts — skip
    }
  }
  return null;
}

export async function detectAndLogin(
  page: Page,
  credentials: UserCredentials,
  logUpdate: (msg: string) => void
) {
  logUpdate('Scanning login form...');

  // STEP 1 - FIND PASSWORD FIELD
  const PASSWORD_SELECTORS = [
    'input[type="password"]',
    'input[name="password"]',
    'input[id="password"]',
    'input[name*="pass"]',
    'input[placeholder*="password" i]',
    'input[placeholder*="Password"]',
  ];
  const passwordSelector = await trySelectors(page, PASSWORD_SELECTORS);

  if (!passwordSelector) {
    throw new LoginFailedError('No password field found on login page.');
  }
  logUpdate(`Found password field: ${passwordSelector}`);

  // STEP 2 - FIND EMAIL/USERNAME FIELD
  const EMAIL_SELECTORS = [
    'input[type="email"]',
    'input[name="email"]',
    'input[id="email"]',
    'input[name*="user"]',
    'input[name*="login"]',
    'input[placeholder*="email" i]',
    'input[placeholder*="Email"]',
    'input[placeholder*="username" i]',
    'input[placeholder*="Username"]',
    'input[id*="email"]',
    'input[id*="user"]',
    'input[type="text"]',
  ];
  const emailSelector = await trySelectors(page, EMAIL_SELECTORS);

  if (emailSelector) {
    logUpdate(`Found email field: ${emailSelector}`);
  }

  // STEP 3 - FIND SUBMIT BUTTON
  const SUBMIT_SELECTORS = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button::-p-text(Sign In)',
    'button::-p-text(Login)',
    'button::-p-text(Log in)',
    'button::-p-text(Continue)',
    'button::-p-text(Submit)',
    'button::-p-text(Sign in)',
    'button::-p-text(LOG IN)',
  ];
  const submitSelector = await trySelectors(page, SUBMIT_SELECTORS);

  if (submitSelector) {
    logUpdate(`Found submit button: ${submitSelector}`);
  }

  // STEP 4 - FILL AND SUBMIT
  if (emailSelector) {
    await page.type(emailSelector, credentials.email, { delay: 30 });
  }
  await page.type(passwordSelector, credentials.password, { delay: 30 });

  if (submitSelector) {
    await page.click(submitSelector);
  } else {
    await page.keyboard.press('Enter');
  }

  try {
    await page.waitForNavigation({ timeout: 5000 }).catch(() => {});
  } catch (e) {
    // catch timeout gracefully
  }

  // STEP 5 - VERIFY LOGIN SUCCESS
  // 1. Check localStorage
  const hasLsToken = await page.evaluate(() => {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && /token|jwt|access_token|auth/i.test(key)) {
        return !!localStorage.getItem(key);
      }
    }
    return false;
  });

  if (hasLsToken) {
    logUpdate('Auth token detected in localStorage');
    logUpdate('Auth type detected: jwt');
    return { type: 'jwt' as const, value: 'true' };
  }

  // 2. Check sessionStorage
  const hasSsToken = await page.evaluate(() => {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && /token|jwt|access_token|auth/i.test(key)) {
        return !!sessionStorage.getItem(key);
      }
    }
    return false;
  });

  if (hasSsToken) {
    logUpdate('Auth token detected in sessionStorage');
    logUpdate('Auth type detected: jwt');
    return { type: 'jwt' as const, value: 'true' };
  }

  // 3. Check cookies
  const cookies = await page.cookies();
  const sessionCookie = cookies.find(c => /session|token|auth|sid|jwt|user/i.test(c.name));

  if (sessionCookie) {
    logUpdate('Login successful — session cookie detected');
    logUpdate('Auth type detected: cookie');
    return { type: 'cookie' as const, value: `${sessionCookie.name}=${sessionCookie.value}` };
  }

  throw new LoginFailedError('Could not detect session cookie or JWT token after login. Try specifying loginFieldSelectors manually.');
}

import fs from 'fs';
import os from 'os';
import path from 'path';

export async function crawl(
  config: ScanConfig,
  onEndpointDiscovered: (ep: DiscoveredEndpoint) => void,
  onStageUpdate?: (stage: string, msg: string) => void,
  signal?: AbortSignal
): Promise<{ endpoints: DiscoveredEndpoint[]; durationMs: number; authType: 'cookie' | 'jwt' | 'unknown'; authValue?: string; stats?: any }> {
  const start = Date.now();
  const targetUrl = config.targetUrl.replace(/\/+$/, '');
  const loginPath = config.loginPath || '/login';
  const pagesToCrawl = config.pagesToCrawl?.length ? config.pagesToCrawl : ['/dashboard'];

  const logUpdate = (msg: string) => {
    console.log(`[CRAWLER] ${msg}`);
    if (onStageUpdate) onStageUpdate('log', `[SCAN] ${msg}`);
  };

  let browser: any;
  let userDataDir: string | undefined;
  let detectedAuth: { type: 'cookie'|'jwt', value: string } | undefined;
  const emptyResult = () => ({
    endpoints: [] as DiscoveredEndpoint[],
    durationMs: Date.now() - start,
    authType: 'unknown' as const,
  });
  try {
    logUpdate('Before launchBrowser');
    
    userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vibeaudit-chrome-"));
    const browserLaunchTimeout = 30_000;
    const launchPromise = puppeteer.launch({
      headless: true,
      userDataDir,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-crash-reporter",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
      ],
    }).then(b => { browser = b; return b; });
    
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Puppeteer launch timeout')), browserLaunchTimeout)
    );

    browser = await Promise.race([launchPromise, timeoutPromise]);
    logUpdate('Browser launched');
  } catch (e: unknown) {
    console.error('[CRAWLER] Failed to launch browser:', e instanceof Error ? e.message : String(e));
    if (browser) {
      try {
        const closePromise = browser.close();
        const closeTimeout = new Promise(r => setTimeout(r, 2000));
        await Promise.race([closePromise, closeTimeout]);
        const proc = browser.process();
        if (proc) proc.kill('SIGKILL');
      } catch (_) {}
    }
    throw e;
  }

  try {
    if (signal?.aborted) {
      await browser.close().catch(console.error);
      return emptyResult();
    }

    let page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    // Set up network interception before any navigation
    const endpoints = await setupInterceptor(page, onEndpointDiscovered);

    // Step 1: Navigate to login page
    logUpdate('Navigating to target');
    try {
      if (signal?.aborted) {
        await browser.close().catch(console.error);
        return emptyResult();
      }
      await page.goto(`${targetUrl}${loginPath}`, { waitUntil: 'networkidle2', timeout: 15000 });
      // Wait for React to hydrate and render inputs before detecting login form
      await page.waitForSelector('input', { timeout: 10000 }).catch(() => {});
      await new Promise(r => setTimeout(r, 2000));
    } catch (e: unknown) {
      console.error('[CRAWLER] Failed to goto login:', e instanceof Error ? e.message : String(e));
      await page.close().catch(() => {});
      throw e;
    }

    // screenshot removed

    // Step 2: Attempt login with victim credentials (User A) to get authenticated session
    logUpdate('Login started');
    try {
      if (signal?.aborted) {
        await browser.close().catch(console.error);
        return emptyResult();
      }
      const { email: customEmail, password: customPassword, submit: customSubmit } = config.loginFieldSelectors || {};
      const hasCustomSelectors = !!(customEmail || customPassword || customSubmit);

      if (hasCustomSelectors) {
        logUpdate('Using custom login field selectors');
        // Resolve login form selectors with sensible defaults if partially provided
        const emailSelector = customEmail || 'input[type="email"], input[name="email"]';
        const passwordSelector = customPassword || 'input[type="password"], input[name="password"]';
        const submitSelector = customSubmit || 'button[type="submit"], input[type="submit"]';

        await withTimeout(
          page.waitForSelector(emailSelector, { timeout: 10000 }),
          10000, 'waitForSelector email'
        );
        await page.type(emailSelector, config.userA.email, { delay: 30 });

        const passwordField = await page.$(passwordSelector);
        if (passwordField) {
          await passwordField.type(config.userA.password, { delay: 30 });
        }

        const submitBtn = await page.$(submitSelector);
        if (submitBtn) {
          await submitBtn.click();
          logUpdate('Clicked submit button');
        } else {
          await page.keyboard.press('Enter');
          logUpdate('Pressed Enter to submit');
        }

        try {
          await withTimeout(
            page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }),
            15000, 'waitForNavigation after login'
          );
        } catch (navErr: unknown) {
          const errorMessage = navErr instanceof Error ? navErr.message : String(navErr);
          logUpdate(`Post-login navigation wait failed: ${errorMessage} — continuing anyway`);
        }
        
        await new Promise(r => setTimeout(r, 2000));
        
        // Check for Auth Type
        const hasLsToken = await page.evaluate(() => {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && /token|jwt|access_token|auth/i.test(key)) return !!localStorage.getItem(key);
          }
          return false;
        });

        if (hasLsToken) {
          logUpdate('Auth token detected in localStorage');
          logUpdate('Auth type detected: jwt');
          logUpdate('Login success');
          detectedAuth = { type: 'jwt', value: 'true' };
        } else {
          const hasSsToken = await page.evaluate(() => {
            for (let i = 0; i < sessionStorage.length; i++) {
              const key = sessionStorage.key(i);
              if (key && /token|jwt|access_token|auth/i.test(key)) return !!sessionStorage.getItem(key);
            }
            return false;
          });
          if (hasSsToken) {
            logUpdate('Auth token detected in sessionStorage');
            logUpdate('Auth type detected: jwt');
            logUpdate('Login success');
            detectedAuth = { type: 'jwt', value: 'true' };
          } else {
            const cookies = await page.cookies();
            const sessionCookie = cookies.find((c: any) => /session|token|auth|sid|jwt|user/i.test(c.name));
            
            if (sessionCookie) {
              logUpdate(`Session cookie found: ${sessionCookie.name}=[REDACTED]`);
              logUpdate('Auth type detected: cookie');
              logUpdate('Login success');
              detectedAuth = { type: 'cookie', value: `${sessionCookie.name}=${sessionCookie.value}` };
            } else {
              logUpdate(`WARNING: No session cookie or JWT token found. Available cookies: ${cookies.map((c: any) => c.name).join(', ')}`);
              logUpdate('[AUTH ERROR] User A/B login failed — check credentials and login path.');
              throw new Error('User A authentication failed. Check credentials and login path.');
            }
          }
        }
      } else {
        detectedAuth = await detectAndLogin(page, config.userA, logUpdate);
        logUpdate('Login success');
      }
    } catch (loginErr: unknown) {
      console.error('[CRAWLER] Login failed:', loginErr);
      const errorMessage = loginErr instanceof Error ? loginErr.message : String(loginErr);
      logUpdate(`Login error: ${errorMessage}`);
      logUpdate('[AUTH ERROR] User A/B login failed — check credentials and login path.');
      throw new Error('User A authentication failed. Check credentials and login path.');
    }

    // Step 3: Crawl authenticated pages
    let pagesVisited = 0;
    const crawlPages = async (extraWait: number) => {
      for (const path of pagesToCrawl) {
        try {
          pagesVisited++;
          if (signal?.aborted) {
            await browser.close().catch(console.error);
            return;
          }
          logUpdate(`Navigating to ${path}...`);
          try {
            if (page.isClosed()) {
              logUpdate(`Page closed unexpectedly, opening new page...`);
              page = await browser.newPage();
              await setupInterceptor(page, onEndpointDiscovered);
            }
            await withTimeout(
              page.goto(`${targetUrl}${path}`, { waitUntil: 'networkidle2' }),
              15000, `goto ${path}`
            );
          } catch (navErr: any) {
            if (navErr.message?.includes('detached Frame') || navErr.message?.includes('Target closed') || navErr.message?.includes('Navigating frame was detached')) {
              logUpdate(`Frame detached or target closed on ${path}, recreating page context...`);
              try { await page.close(); } catch {}
              page = await browser.newPage();
              await setupInterceptor(page, onEndpointDiscovered);
              await withTimeout(
                page.goto(`${targetUrl}${path}`, { waitUntil: 'networkidle2' }),
                15000, `goto ${path}`
              );
            } else {
              throw navErr;
            }
          }

          // Wait for at least one link to appear (SPA hydration)
          try {
            await page.waitForSelector('a[href]', { timeout: 5000 });
          } catch (_) {
            logUpdate(`No links appeared on ${path} within 5s — continuing`);
          }

          // Additional SPA hydration wait
          await new Promise(r => setTimeout(r, extraWait));

          if (page.isClosed()) continue;
          const currentUrl = page.url();
          logUpdate(`After navigating to ${path}, actual URL: ${currentUrl}`);
          // screenshot removed

          // Generically detect parameterized links via regex
          const allLinks = await page.$$eval('a[href]', (anchors: any[]) =>
            anchors.map((a: any) => a.getAttribute('href') || '')
          );
          const regexLinks = allLinks.filter((href: string) =>
            PARAMETERIZED_LINK_PATTERN.test(href)
          );

          // Also scan for links using resource selectors
          const selectorLinks: string[] = [];
          for (const sel of RESOURCE_LINK_SELECTORS) {
            try {
              const found = await page.$$eval(sel, (anchors: any[]) =>
                anchors.map((a: any) => a.getAttribute('href') || '')
              );
              selectorLinks.push(...found);
            } catch (_) {}
          }

          // Deduplicate
          const paramLinks = [...new Set([...regexLinks, ...selectorLinks.filter(Boolean)])];
          logUpdate(`Found ${paramLinks.length} parameterized/resource link(s) on ${path}`);

          // Click all parameterized links to trigger API calls
          if (paramLinks.length > 0) {
            for (const link of paramLinks) {
              try {
                if (signal?.aborted) {
                  await browser.close().catch(console.error);
                  return;
                }
                logUpdate(`Clicking into ${link} to discover nested endpoints...`);
                await page.evaluate((href: string) => {
                  const doc = (globalThis as any).document;
                  const el = [...doc.querySelectorAll('a')]
                    .find(a => a.getAttribute('href') === href);
                  if (el) el.click();
                }, link);
                await new Promise(r => setTimeout(r, 2000));
                
                const newUrl = page.url();
                logUpdate(`After link click, URL: ${newUrl}`);

                try {
                  const urlObj = new URL(newUrl);
                  const pathParts = urlObj.pathname.split('/').filter(Boolean);
                  
                  if (pathParts.length >= 2) {
                    const resourceType = pathParts[pathParts.length - 2];
                    const resourceId = pathParts[pathParts.length - 1];
                    
                    const probes = [
                      `/api/${resourceType}/${resourceId}`,
                      `/api/v1/${resourceType}/${resourceId}`,
                      `/api/${resourceType}`
                    ];
                    
                    for (const probe of probes) {
                      logUpdate(`Probing API route: ${probe}`);
                    }
                    
                    await page.evaluate(async (probeUrls: string[]) => {
                      for (const p of probeUrls) {
                        try { await fetch(p, { credentials: 'include', signal: AbortSignal.timeout(10000) }); } catch {}
                      }
                    }, probes);
                    await new Promise(r => setTimeout(r, 1000));
                  }
                } catch (e) {
                  // Ignore URL parsing errors
                }

                if (page.url() !== currentUrl) {
                   await page.goBack({ waitUntil: 'networkidle2', timeout: 8000 }).catch(() => {});
                   await new Promise(r => setTimeout(r, 1000));
                }
              } catch (_) {
                logUpdate(`Failed to click parameterized link: ${link}`);
              }
            }
          }

          // Force API discovery via page.evaluate (cookies auto-attached)
          logUpdate('Probing common API routes from browser context...');
          try {
            const discoveredApiPaths = endpoints
              .filter(ep => ep.path.startsWith('/api/'))
              .map(ep => ep.path);
            const allApiPaths = [...new Set([...discoveredApiPaths, ...COMMON_API_PATHS])];
            await page.evaluate(async (paths: string[]) => {
              for (const p of paths) {
                try { await fetch(p, { credentials: 'include', signal: AbortSignal.timeout(10000) }); } catch {}
              }
            }, allApiPaths);
            await new Promise(r => setTimeout(r, 1000));
          } catch (_) {
            logUpdate('Direct fetch evaluation failed');
          }

        } catch (err: unknown) {
          console.error(`[CRAWLER] Failed crawling ${path}:`, err);
          // screenshot removed
        }
      }
    };

    // First crawl attempt
    await crawlPages(2000);
    if (signal?.aborted) {
      await browser.close().catch(console.error);
      return emptyResult();
    }

    // Retry logic: if 0 endpoints found, try once more with longer waits
    const authEndpoints = endpoints.filter(ep => ep.isAuthenticated);
    if (authEndpoints.length === 0 && endpoints.length === 0) {
      logUpdate('No endpoints found — retrying crawl with longer waits...');
      if (onStageUpdate) onStageUpdate('log', '⚠️ No endpoints found — retrying crawl...');
      await crawlPages(5000);
      if (signal?.aborted) {
        await browser.close().catch(console.error);
        return emptyResult();
      }
    }

    // Endpoint Fuzzer: intelligently append IDs to routes identified as 404 or 400
    const fuzzTargets = endpoints.filter(ep => {
      const isError = ep.statusCode >= 400 || ep.statusCode === 0;
      const hasNullId = ep.path.endsWith('/null') || ep.path.endsWith('/undefined') || ep.path.endsWith('/0');
      const isBaseRoute = !ep.path.includes('.') && ep.path.split('/').length >= 3;
      return isError && (hasNullId || isBaseRoute);
    });

    if (fuzzTargets.length > 0 && page && !page.isClosed()) {
      logUpdate(`[FUZZER] Fuzzing ${fuzzTargets.length} potential parameterized endpoints...`);
      const fuzzPaths = new Set<string>();
      
      for (const ep of fuzzTargets) {
        // Strip invalid IDs to get the base path
        let basePath = ep.path.replace(/\/(null|undefined|0)$/i, '');
        // Remove trailing slashes
        basePath = basePath.replace(/\/+$/, '');
        
        // Guess common numeric IDs
        fuzzPaths.add(`${basePath}/1`);
        fuzzPaths.add(`${basePath}/2`);
        fuzzPaths.add(`${basePath}/3`);
        fuzzPaths.add(`${basePath}/123`);
        
        // Guess some common string/UUID formats if the API expects them
        fuzzPaths.add(`${basePath}/test`);
        
        // Inject harvested IDs from all intercepted API responses
        for (const id of harvestedIds) {
          fuzzPaths.add(`${basePath}/${id}`);
        }
      }

      try {
        await page.evaluate(async (paths: string[]) => {
          for (const p of paths) {
            try { await fetch(p, { credentials: 'include', signal: AbortSignal.timeout(5000) }); } catch {}
          }
        }, Array.from(fuzzPaths));
        // Wait for interceptor to catch the fuzzing responses
        await new Promise(r => setTimeout(r, 3000));
      } catch (_) {
        logUpdate('[FUZZER] Failed to execute endpoint fuzzer in browser context');
      }
    }
    
    const dedupedEndpoints = deduplicateEndpoints(endpoints);
    logUpdate(`Crawl complete. Found ${endpoints.length} endpoints (${dedupedEndpoints.length} unique patterns after dedup)`);
    
    let finalAuthType = detectedAuth?.type || 'unknown';
    if (endpoints.some(ep => ep.authMethod === 'jwt')) {
      finalAuthType = 'jwt';
    }

    return {
      endpoints: dedupedEndpoints,
      durationMs: Date.now() - start,
      authType: finalAuthType,
      authValue: detectedAuth?.value,
      capturedIds,
      stats: {
        pagesVisited: pagesVisited,
        endpointsDiscovered: endpoints.length,
        uniqueEndpoints: dedupedEndpoints.length,
        parameterizedEndpoints: dedupedEndpoints.filter(ep => normalizePath(ep.path).includes(':id')).length,
      }
    };
  } finally {
    if (browser) {
      await browser.close().catch(console.error);
    }
    if (userDataDir) {
      try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (e) { console.error('Failed to cleanup userDataDir', e); }
    }
  }
}
