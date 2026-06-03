import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { crawl } from './crawler/crawler';
import { runBOLAAttack } from './attack/bola';
import { generatePatch } from './ai/patch';
import { generatePlaywrightTest } from './tests/playwright-generator';
import { createSecurityPR } from './github/pr';
import { verifyPatch } from './verify/verify';
import { formatSensitiveField } from './attack/sensitive';
import { ScanConfig, SSEEvent, SSEStage, SSEType } from './types';
import { sleep } from './utils/agent';
import { promises as dns } from 'dns';
import crypto from 'crypto';
import { redactHeaders } from './utils/redact';
import { isPrivateIP } from './utils/agent';
dotenv.config();

process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT]', err);
});

process.on('unhandledRejection', (err) => {
  console.error('[UNHANDLED_REJECTION]', err);
});

interface ActiveScan {
  events: SSEEvent[];
  listeners: Set<(event: SSEEvent) => void>;
  completed: boolean;
  startedAt: number;
}

const activeScans = new Map<string, ActiveScan>();

// Cleanup scans after 10 minutes (absolute TTL)
const activeScansInterval = setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [id, scan] of activeScans.entries()) {
    if (scan.startedAt < cutoff) {
      activeScans.delete(id);
    }
  }
}, 60_000);

const app = express();
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || 'http://localhost:3000'
}));
app.use(express.json());

function requireApiKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const apiKey = req.header('X-API-Key') || '';
  const expectedKey = process.env.VIBEAUDIT_API_KEY || '';
  const providedBuffer = Buffer.from(apiKey);
  const expectedBuffer = Buffer.from(expectedKey);

  let isMatch = false;
  if (providedBuffer.length === expectedBuffer.length) {
    isMatch = crypto.timingSafeEqual(providedBuffer, expectedBuffer);
  } else {
    crypto.timingSafeEqual(expectedBuffer, expectedBuffer);
  }

  if (!isMatch || expectedBuffer.length === 0) {
    res.status(401).json({ error: 'Unauthorized: Invalid or missing X-API-Key' });
    return;
  }
  next();
}

function writeSSE(res: express.Response, data: string) {
  if (!res.writableEnded && !res.destroyed) {
    res.write(data);
  }
}

function emitSSE(res: express.Response, data: any, scanId?: string) {
  writeSSE(res, `data: ${JSON.stringify(data)}\n\n`);
  // Flush body buffer — works with or without compression middleware
  if (typeof (res as any).flush === 'function') {
    (res as any).flush();
  }
  // Buffer event and broadcast to reconnected listeners
  if (scanId) {
    const scan = activeScans.get(scanId);
    if (scan) {
      scan.events.push(data);
      if (scan.events.length > 1000) scan.events.shift();
      scan.listeners.forEach(fn => fn(data));
    }
  }
}

app.get('/scan/:scanId/stream', requireApiKey, (req, res) => {
  const { scanId } = req.params;
  const scan = activeScans.get(scanId as string);

  if (!scan) {
    res.status(404).json({ error: 'Scan not found or expired' });
    return;
  }

  // SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_ORIGIN || 'http://localhost:3000');
  res.flushHeaders();

  // Replay all buffered events immediately
  for (const event of scan.events) {
    writeSSE(res, `data: ${JSON.stringify(event)}\n\n`);
  }

  // If already completed, close stream
  if (scan.completed) {
    res.end();
    return;
  }

  // Subscribe to future events
  const listener = (event: SSEEvent) => {
    writeSSE(res, `data: ${JSON.stringify(event)}\n\n`);
    if (event.stage === 'done' && event.type === 'complete') {
      res.end();
      scan.listeners.delete(listener);
    }
  };

  scan.listeners.add(listener);
  req.on('close', () => {
    scan.listeners.delete(listener);
  });
});

export async function validateScanInput(body: any): Promise<string | null> {
  // Returns error message or null if valid
  
  const { targetUrl, userA, userB } = body;

  // 1. URL must exist and be a string
  if (!targetUrl || typeof targetUrl !== 'string') {
    return 'Target URL is required.';
  }

  // 2. URL must parse correctly
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return 'Target URL is not a valid URL.';
  }

  // 3. Must be http or https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return 'Target URL must use http or https.';
  }

  // 4. SSRF protection — block private/internal ranges via DNS
  const hostname = parsed.hostname.toLowerCase();
  
  try {
    const lookupResult = await dns.lookup(hostname);
    const resolvedIp = lookupResult.address;
    
    if (isPrivateIP(resolvedIp)) {
      return 'Target URL resolves to a private or blocked network address.';
    }
  } catch (err) {
    return 'Target URL failed DNS resolution.';
  }

  // 5. Credentials must exist
  if (!userA?.email || !userA?.password) {
    return 'User A email and password are required.';
  }
  if (!userB?.email || !userB?.password) {
    return 'User B email and password are required.';
  }

  // 6. Basic email format
  if (!userA.email.includes('@') || !userB.email.includes('@')) {
    return 'User email addresses are not valid.';
  }

  // 7. Max length protection
  if (targetUrl.length > 500) {
    return 'Target URL is too long.';
  }
  if (userA.password.length > 200 || userB.password.length > 200) {
    return 'Password is too long.';
  }

  // 8. GitHub repo name — prevent path traversal
  if (body.githubRepoName) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(body.githubRepoName)) {
      return 'GitHub repo name contains invalid characters.';
    }
  }
  if (body.githubRepoOwner) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(body.githubRepoOwner)) {
      return 'GitHub repo owner contains invalid characters.';
    }
  }
  if (body.githubBaseBranch) {
    if (!/^[a-zA-Z0-9_.-]+$/.test(body.githubBaseBranch)) {
      return 'GitHub base branch contains invalid characters.';
    }
  }

  if (body.pagesToCrawl !== undefined) {
    if (!Array.isArray(body.pagesToCrawl)) {
      return 'pagesToCrawl must be an array';
    }
    if (!body.pagesToCrawl.every((p: unknown) => typeof p === 'string')) {
      return 'pagesToCrawl must contain only strings';
    }
  }

  return null; // valid
}

const rateLimitMap = new Map<string, { count: number; firstRequestTime: number }>();

const rateLimitInterval = setInterval(() => {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now - record.firstRequestTime > windowMs) {
      rateLimitMap.delete(ip);
    }
  }
}, 5 * 60 * 1000);

const cleanup = () => {
  clearInterval(activeScansInterval);
  clearInterval(rateLimitInterval);
  process.exit(0);
};

process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);
const MAX_CONCURRENT_SCANS = 2;
let activeCount = 0;

function scanLimiter(req: express.Request, res: express.Response, next: express.NextFunction) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const max = 10;
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, firstRequestTime: now });
    return next();
  }
  
  const record = rateLimitMap.get(ip)!;
  if (now - record.firstRequestTime > windowMs) {
    record.count = 1;
    record.firstRequestTime = now;
    return next();
  }
  
  record.count++;
  if (record.count > max) {
    res.status(429).json({ error: 'Too many scans from this IP, please try again after 15 minutes.' });
    return;
  }
  next();
}

app.post('/scan', requireApiKey, scanLimiter, async (req, res) => {
  const validationError = await validateScanInput(req.body);
  if (validationError) {
    res.status(400).json({ error: validationError });
    return;
  }
  if (activeCount >= MAX_CONCURRENT_SCANS) {
    res.status(429).json({ error: 'Scanner busy. Try again in a moment.' });
    return;
  }
  activeCount++;
  
  const scanId = crypto.randomUUID();
  let heartbeat: NodeJS.Timeout | null = null;
  const aborted = { value: false };

  function emit(stage: SSEStage, type: SSEType, message: string, payload?: any) {
    if (aborted.value) return;
    emitSSE(res, { stage, type, message, payload, timestamp: Date.now() }, scanId);
  }

  try {
  console.log('[SCAN] Request received');

  activeScans.set(scanId, {
    events: [],
    listeners: new Set(),
    completed: false,
    startedAt: Date.now(),
  });

  // SSE setup
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders(); // ← correct here, one-time header flush

  // Disable Nagle's algorithm so small SSE chunks aren't batched
  res.socket?.setNoDelay(true);

  // Emit scanId as the very first event so the frontend can capture it
  emit('preflight', 'log', `Scan ID: ${scanId}`, { scanId });

  const abortController = new AbortController();
  const { signal } = abortController;

  req.on('close', () => { 
    aborted.value = true;
    abortController.abort();
    if (heartbeat) clearInterval(heartbeat);
  });

  // Heartbeat ping every 2 seconds
  heartbeat = setInterval(() => {
    if (!aborted.value) {
      writeSSE(res, ': heartbeat\n\n');
      if (typeof (res as any).flush === 'function') {
        (res as any).flush();
      }
    }
  }, 2000);

  const scanStartTime = Date.now();
  let exploitConfirmedTime: number | null = null;

  // ── PARSE CONFIG ──────────────────────────────
  const { targetUrl, userA, userB, loginPath, pagesToCrawl, loginFieldSelectors, authType, githubRepoOwner, githubRepoName, githubBaseBranch, githubToken: bodyGithubToken } = req.body;
    
    if (!targetUrl) {
      emit('preflight', 'error', 'targetUrl is required');
      throw new Error('targetUrl is required');
    }
    if (!userA?.email || !userA?.password) {
      emit('preflight', 'error', 'userA credentials (email, password) are required');
      throw new Error('userA credentials are required');
    }
    if (!userB?.email || !userB?.password) {
      emit('preflight', 'error', 'userB credentials (email, password) are required');
      throw new Error('userB credentials are required');
    }

    const config: ScanConfig = {
      targetUrl: targetUrl.replace(/\/+$/, ''),
      userA,
      userB,
      loginPath: loginPath || '/login',
      pagesToCrawl: pagesToCrawl?.length ? pagesToCrawl : ['/dashboard'],
      loginFieldSelectors,
      authType: authType || 'auto',
      githubToken: bodyGithubToken || process.env.GITHUB_TOKEN,
      githubRepoOwner,
      githubRepoName,
      githubBaseBranch: githubBaseBranch || 'main',
    };

    config.pagesToCrawl = (config.pagesToCrawl || ['/dashboard'])
      .flatMap((p: string) => p.split(/[\n,\s]+/))
      .map((p: string) => p.trim())
      .filter((p: string) => p.startsWith('/'));

    if (config.pagesToCrawl.length === 0) {
      config.pagesToCrawl = ['/dashboard'];
    }

    // ── PREFLIGHT ──────────────────────────────
    emit('preflight', 'log', 'Scanner initialized');
    await sleep(250);
    emit('preflight', 'log', `Target: ${config.targetUrl}`);
    await sleep(250);
    emit('preflight', 'log', `User A: ${config.userA.email}`);
    await sleep(150);
    emit('preflight', 'log', `User B: ${config.userB.email}`);
    await sleep(150);
    emit('preflight', 'log', `Login path: ${config.loginPath}`);
    await sleep(150);
    emit('preflight', 'log', `Pages to crawl: ${config.pagesToCrawl!.join(', ')}`);
    await sleep(200);

    const hasGithub = !!(config.githubToken) && !!(config.githubRepoOwner && config.githubRepoName);
    const hasGroq = !!(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY.length > 10);

    emit('preflight', 'log', hasGithub ? 'GitHub integration ready' : 'GitHub integration not configured (PR step will be skipped)');
    await sleep(200);
    emit('preflight', 'log', hasGroq ? 'AI engine connected' : 'AI engine not configured (will use deterministic patch)');
    await sleep(200);
    emit('preflight', 'log', `Base branch: ${config.githubBaseBranch || 'main'}`);
    await sleep(200);
    emit('preflight', 'complete', 'Preflight checks passed. Starting scan.');

    // ── CRAWLER ────────────────────────────────
    if (aborted.value) {
      emit('done', 'error', 'Scan cancelled — client disconnected.');
      return;
    }
    console.log('[SCAN] Starting crawler');
    emit('crawler', 'log', 'Launching browser');
    
    const crawlerPromise = crawl(
      config,
      (ep) => {
        const auth = ep.isAuthenticated ? ' [AUTH]' : '';
        emit('crawler', 'endpoint', `${ep.method} ${ep.path}${auth} → ${ep.statusCode}`, { ...ep, requestHeaders: redactHeaders(ep.requestHeaders) });
      },
      (stage, msg) => {
        if (stage === 'log') {
          console.log(msg); // log to terminal
          const text = msg.replace('[SCAN] ', '');
          
          if (text === 'Browser launched') {
            emit('crawler', 'log', 'Launching browser');
          } else if (text === 'Navigating to target') {
            emit('crawler', 'log', 'Navigating to target');
          } else if (text === 'Login started') {
            emit('crawler', 'log', 'Login started');
          } else if (text === 'Login success') {
            emit('crawler', 'complete', 'Login success');
          } else {
            emit('crawler', 'log', text);
          }
        }
      },
      abortController.signal
    );

    let crawlTimeoutId: NodeJS.Timeout;
    const timeoutPromise = new Promise<never>((_, reject) => {
      crawlTimeoutId = setTimeout(() => {
        abortController.abort();
        reject(new Error('Crawler timeout'));
      }, 60000);
    });
    
    crawlerPromise.catch(() => {});
    const { endpoints, durationMs, authType: crawlerAuthType } = await Promise.race([crawlerPromise, timeoutPromise]).finally(() => clearTimeout(crawlTimeoutId));

    if (crawlerAuthType === 'jwt') {
      emit('crawler', 'log', 'Detected JWT authentication — switching to Bearer token mode');
    }

    emit('crawler', 'complete', `Discovery complete: ${endpoints.length} API endpoints found in ${(durationMs / 1000).toFixed(1)}s`, { endpoints, durationMs });
    await sleep(400);

    // ── ATTACK ────────────────────────────────
    if (aborted.value) {
      emit('done', 'error', 'Scan cancelled — client disconnected.');
      return;
    }
    console.log('[SCAN] Attack engine start');
    emit('attack', 'log', 'Running BOLA attacks');
    const effectiveAuthType =
      config.authType && config.authType !== 'auto'
        ? config.authType
        : crawlerAuthType;

    const result = await runBOLAAttack(
      config,
      endpoints,
      effectiveAuthType,
      (...args: any[]) => {
        if (args.length >= 3) emit(args[0], args[1], args[2], args[3]);
        else emit('attack', 'log', args[0], args[1]);
      },
      abortController.signal
    );

    if (result.reason !== 'vulnerable' || !result.finding) {
      console.log(`[SCAN] Scan completed cleanly (reason: ${result.reason})`);
      emit('attack', 'complete', 'No exploitable BOLA vulnerability found on tested endpoints.');
      
      if (!aborted.value) {
        emitSSE(res, {
          stage: 'complete',
          type: 'clean',
          message: 'Scan complete — no exploitable vulnerabilities found',
          payload: { reason: result.reason, endpointsScanned: endpoints.length },
          timestamp: Date.now()
        }, scanId);

        emitSSE(res, {
          stage: 'summary',
          type: 'result',
          endpointsFound: endpoints.length,
          vulnerabilities: 0,
          attacksAttempted: endpoints.length,
          targetUrl: config.targetUrl,
          scanDurationMs: Date.now() - scanStartTime,
          timeToExploitMs: null,
          timestamp: Date.now()
        }, scanId);
      }

      const cleanScan = activeScans.get(scanId);
      if (cleanScan) cleanScan.completed = true;

      if (heartbeat) clearInterval(heartbeat);
      res.end();
      return;
    }

    const finding = result.finding;
    exploitConfirmedTime = Date.now();

    // Stream sensitive fields one by one for dramatic effect
    emit('attack', 'log', '── Stolen Record Data ──────────────────');
    await sleep(300);

    for (const field of finding.sensitiveFields) {
      let redactedValue = '';
      if (typeof field.value === 'string') {
        redactedValue = field.value.substring(0, 2) + '***';
      } else if (typeof field.value === 'number') {
        redactedValue = '[NUMBER]';
      } else if (typeof field.value === 'boolean') {
        redactedValue = '[BOOLEAN]';
      } else {
        redactedValue = '[REDACTED]';
      }
      emit('attack', 'data', `${field.key} (${field.category}): ${redactedValue}`, { key: field.key, category: field.category, redactedPreview: redactedValue });
      await sleep(200);
    }

    await sleep(2000);
    emit('attack', 'log', `CVSS 9.3 Critical — ${finding.sensitiveFields.length} sensitive fields exposed`);
    await sleep(1000);
    emit('attack', 'log', `Reproduction: ${finding.curlReproduction}`);
    await sleep(500);

    // Emit full finding metadata for frontend history capture
    emit('attack', 'finding', 'BOLA Finding', {
      endpoint: finding.endpoint,
      confidenceScore: finding.confidenceScore,
      sensitiveFields: finding.sensitiveFields.map(f => ({ key: f.key, category: f.category })),
      cvssScore: finding.cvssScore,
      attackerAuthenticated: finding.attackerAuthenticated,
    });

    // ── AI PATCH ──────────────────────────────
    if (aborted.value) {
      emit('done', 'error', 'Scan cancelled — client disconnected.');
      return;
    }
    const patch = await generatePatch(
      finding,
      config,
      (msg, payload) => emit('ai', payload ? 'patch' : 'log', msg, payload),
      abortController.signal
    );

    // ── PLAYWRIGHT TEST ───────────────────────
    const playwrightTest = generatePlaywrightTest(finding, config);
    emit('ai', 'log', '[TEST] Playwright regression test generated ✓');
    emit('ai', 'data', 'Regression test', { regressionTest: playwrightTest });
    
    console.log('[PATCH RESULT]', {
      hasPatchedCode: !!patch.patchedCode,
      hasFilePath: !!patch.filePath,
      hasTestCode: !!playwrightTest,
      patchValidated: patch.patchValidated
    });

    // ── GITHUB PR ─────────────────────────────
    if (aborted.value) {
      emit('done', 'error', 'Scan cancelled — client disconnected.');
      return;
    }
    let prUrl: string | null = null;

    const hasToken = !!(config.githubToken);
    const hasRepo = !!(config.githubRepoOwner && config.githubRepoName);
    if (!hasToken || !hasRepo) {
      // skip PR silently
    } else if (!patch.patchedCode || !patch.filePath) {
      emit('github', 'log', '[GITHUB] No patch content. Skipping PR.');
    } else {
      console.log('[PR GUARD] patchValidated value:', patch?.patchValidated);
      emit('github', 'log', '[GITHUB] Preparing Pull Request...');
      await sleep(1000);

      try {
        console.log('[ORCHESTRATOR] About to create PR...');
        prUrl = await createSecurityPR(
          patch,
          playwrightTest,
          finding,
          config,
          (msg) => emit('github', 'log', msg),
          abortController.signal
        );
        console.log('[ORCHESTRATOR] PR function returned:', prUrl);
        if (prUrl) {
          emit('github', 'complete', `Pull Request opened: ${prUrl}`, { prUrl });
        } else {
          emit('github', 'complete', 'PR skipped — patch and test are ready for manual commit.');
        }
      } catch (err: unknown) {
        console.error('[SCAN_ERROR]', err);
        const errorMessage = err instanceof Error ? err.message : String(err);
        emit('github', 'error', `GitHub PR failed: ${errorMessage}`);
      }
    }

    // ── VERIFY ────────────────────────────────
    const patched = await verifyPatch(
      config.targetUrl,
      finding.endpoint,
      finding.attackerToken,
      effectiveAuthType,
      (msg) => emit('verify', 'log', msg),
      abortController.signal
    );

    if (patched) {
      emit('verify', 'complete', '403 Confirmed. The vulnerability has been patched.', { prUrl, verificationStatus: '403_confirmed' });
    } else {
      emit('verify', 'complete', 'Verification pending — patch has not been deployed to target yet.', { prUrl, verificationStatus: 'patch_failed' });
    }

    // ── DONE ──────────────────────────────────
    console.log('[SCAN] Scan completed');
    emit('done', 'complete', 'Scan completed');

    if (!aborted.value) {
      emitSSE(res, {
        stage: 'summary',
        type: 'result',
        endpointsFound: endpoints.length,
        vulnerabilities: 1,
        attacksAttempted: endpoints.length,
        targetUrl: config.targetUrl,
        scanDurationMs: Date.now() - scanStartTime,
        timeToExploitMs: exploitConfirmedTime ? exploitConfirmedTime - scanStartTime : null,
        timestamp: Date.now(),
        // Pass everything directly in summary for safety
        endpoint: finding.endpoint,
        sensitiveFields: finding.sensitiveFields.map(f => f.key),
        confidenceScore: finding.confidenceScore,
        patch: patch.patchedCode,
        patchSource: patch.patchSource,
        regressionTest: playwrightTest,
        prUrl: prUrl,
      }, scanId);
      res.end();
    }

  } catch (err: unknown) {
    console.error('[SCAN_ERROR]', err);
    const errorMessage = err instanceof Error ? err.message : String(err);
    emit('done', 'error', `[ERROR] ${errorMessage}`);
    emit('done', 'error', `Scan failed: ${errorMessage}`);
  } finally {
    activeCount = Math.max(0, activeCount - 1);

    const doneScan = activeScans.get(scanId);
    if (doneScan) doneScan.completed = true;
    setTimeout(() => activeScans.delete(scanId), 30000);
    
    if (heartbeat) clearInterval(heartbeat);
    if (!res.writableEnded) {
      res.end();
    }
  }
});

app.get('/health', (_, res) => res.json({
  status: 'ok',
}));

const PORT = Number(process.env.PORT) || 4000;

if (!process.env.VIBEAUDIT_API_KEY || process.env.VIBEAUDIT_API_KEY.length < 32) {
  throw new Error('VIBEAUDIT_API_KEY must be at least 32 characters');
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  VibeAudit Scanner v2.0.0`);
  console.log(`  → http://localhost:${PORT}`);
  console.log(`  → POST /scan { targetUrl, userA, userB, ... }`);
  console.log(`  → GET  /health\n`);
});
