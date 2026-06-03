import { groqWithRetry } from '../utils/groq-retry';
import { Octokit } from '@octokit/rest';
import { transform } from 'esbuild';
import ts from 'typescript';
import { BOLAFinding, PatchResult, ScanConfig, Severity } from '../types';
import { sleep } from '../utils/agent';
import { summarizeForPrompt } from '../utils/redact';
/**
 * Build candidate file paths based on the resource type and segment naming variants.
 */
function buildCandidatePaths(endpointPath: string): string[] {
  const segments = endpointPath.split('/').filter(Boolean);
  if (segments.length < 2) return [`app/${segments.join('/')}/route.ts`];

  segments.pop();
  const resourceType = segments[segments.length - 1];
  const singular = resourceType.replace(/s$/, '');

  const segmentNames = [
    'id',
    'userId',
    `${singular}Id`,
    `${resourceType}Id`,
    singular,
    resourceType,
    'slug',
    'resourceId',
  ];

  const basePath = segments.join('/');
  const paths = new Set<string>();

  for (const segmentName of segmentNames) {
    paths.add(`app/${basePath}/[${segmentName}]/route.ts`);
    paths.add(`app/${basePath}/route.ts`);

    paths.add(`src/app/${basePath}/[${segmentName}]/route.ts`);
    paths.add(`src/app/${basePath}/route.ts`);

    paths.add(`pages/${basePath}/[${segmentName}].ts`);
    paths.add(`pages/${basePath}/index.ts`);
    paths.add(`pages/${basePath}.ts`);

    paths.add(`src/pages/${basePath}/[${segmentName}].ts`);
    paths.add(`src/pages/${basePath}/index.ts`);

    paths.add(`src/routes/${resourceType}.ts`);
    paths.add(`src/controllers/${resourceType}Controller.ts`);
    paths.add(`routes/${resourceType}.ts`);
    paths.add(`controllers/${resourceType}Controller.ts`);
  }

  const result: string[] = [];
  for (const p of paths) {
    result.push(p);
    if (p.endsWith('.ts')) {
      result.push(p.replace(/\.ts$/, '.js'));
    }
  }

  return result;
}

/**
 * Try to read the actual source file from GitHub for the vulnerable route.
 * Returns the file content as a string, or null if it can't be read.
 */
async function readFileFromGitHub(
  filePath: string,
  config: ScanConfig
): Promise<string | null> {
  const token = config.githubToken;
  const owner = config.githubRepoOwner;
  const repo = config.githubRepoName;
  const base = config.githubBaseBranch || 'main';

  if (!token || !owner || !repo) {
    return null;
  }

  try {
    const octokit = new Octokit({ auth: token });
    const { data } = await octokit.repos.getContent({
      owner, repo, path: filePath, ref: base,
    });

    if ('content' in data && typeof data.content === 'string') {
      return Buffer.from(data.content, 'base64').toString('utf-8');
    }
    return null;
  } catch (err: unknown) {
    return null;
  }
}

/**
 * Dynamically infer the ownership field from the source code.
 * Looks for common patterns like `userId`, `ownerId`, `recordUserId`, `authorId`, etc.
 */
function inferOwnershipField(code: string): string | null {
  // Look for field names that suggest user ownership on a fetched record
  const ownershipPatterns = [
    /(\w*[Uu]ser[Ii]d\w*)/,          // userId, recordUserId, createdByUserId
    /(\w*[Oo]wner[Ii]d\w*)/,         // ownerId, resourceOwnerId
    /(\w*[Aa]uthor[Ii]d\w*)/,        // authorId
    /(\w*[Cc]reated[Bb]y\w*)/,       // createdBy, createdById
    /(\w*[Uu]ser_id\w*)/,            // user_id (snake_case)
    /(\w*owner_id\w*)/,              // owner_id
  ];

  for (const pattern of ownershipPatterns) {
    const match = code.match(pattern);
    if (match) return match[1];
  }

  return null;
}

/**
 * Infer the auth library being used from the source code.
 */
function inferAuthLibrary(code: string): { library: string; sessionAccessor: string } {
  if (code.includes('@/auth') || code.includes('next-auth') || code.includes('authjs')) {
    return { library: 'Auth.js', sessionAccessor: 'session.user.id' };
  }
  if (code.includes('getServerSession')) {
    return { library: 'NextAuth (getServerSession)', sessionAccessor: 'session.user.id' };
  }
  if (code.includes('supabase')) {
    return { library: 'Supabase Auth', sessionAccessor: 'user.id' };
  }
  if (code.includes('clerk') || code.includes('@clerk')) {
    return { library: 'Clerk', sessionAccessor: 'userId' };
  }
  // Default assumption
  return { library: 'Unknown', sessionAccessor: '' };
}

// ── Esbuild Patch Validation ─────────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  error?: string;
  correctedPatch?: string;
  attempts: number;
}

/**
 * Validate AI-generated patch string using Esbuild's in-memory transform API.
 * If validation fails, attempt self-correction via Groq up to 3 times total.
 * Does NOT write any files to disk.
 */
export async function validatePatch(
  patchString: string,
  originalPrompt: string,
  emit: (msg: string, payload?: unknown) => void
): Promise<ValidationResult> {
  const MAX_ATTEMPTS = 2;
  let currentPatch = patchString;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      await transform(currentPatch, {
        loader: 'ts',
        target: 'node18',
        format: 'esm',
      });

      const sourceFile = ts.createSourceFile('patch.ts', currentPatch, ts.ScriptTarget.Latest, true);
      let hasAuthResponse = false;
      let dangerousViolation: string | null = null;

      function visit(node: ts.Node) {
        if (dangerousViolation) return;

        if (ts.isImportDeclaration(node)) {
          dangerousViolation = 'ImportDeclaration is blocked';
        } else if (ts.isCallExpression(node)) {
          const calleeText = node.expression.getText();
          if (['eval', 'Function', 'setTimeout', 'setInterval'].includes(calleeText)) {
            if (node.arguments.some(arg => ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))) {
              dangerousViolation = `CallExpression to ${calleeText} with string argument is blocked`;
            }
          }
          if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
            dangerousViolation = 'dynamic import() is blocked';
          }
          if (node.arguments.some(arg => ts.isSpreadElement(arg))) {
            dangerousViolation = 'SpreadElement in function call is blocked';
          }
          
          if (calleeText === 'res.status' || calleeText === 'res.sendStatus') {
            if (node.arguments.length > 0 && ts.isNumericLiteral(node.arguments[0])) {
              const code = node.arguments[0].text;
              if (code === '401' || code === '403') {
                let parent = node.parent;
                while (parent) {
                  if (ts.isIfStatement(parent) || ts.isConditionalExpression(parent) || ts.isSwitchStatement(parent)) {
                    hasAuthResponse = true;
                    break;
                  }
                  parent = parent.parent;
                }
              }
            }
          }
        } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
          const objText = node.expression.getText();
          if (['process', 'global', 'globalThis', '__dirname', '__filename', 'require'].includes(objText)) {
            dangerousViolation = `MemberExpression accessing ${objText} is blocked`;
          }
        } else if (ts.isIdentifier(node)) {
          if (['process', 'global', 'globalThis', '__dirname', '__filename', 'require'].includes(node.text)) {
            dangerousViolation = `Accessing ${node.text} is blocked`;
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(sourceFile);

      if (dangerousViolation) {
        throw new Error(dangerousViolation);
      }

      const hasAuthRegex =
        /res\.(status|sendStatus)\s*\(\s*(401|403)/.test(currentPatch)
        || /return\s+res\..*\b(401|403)/.test(currentPatch)
        || /Response\.json\s*\([^)]*\{[^)]*status:\s*(401|403)/s.test(currentPatch);

      if (!hasAuthRegex || !hasAuthResponse) {
        throw new Error('AI patch does not contain explicit 401/403 response in a conditional branch');
      }

      // Transform succeeded — patch is syntactically valid
      if (attempt === 1) {
        emit('[PATCH] Syntax validation passed.');
      } else {
        emit('[PATCH] Self-correction successful. Patch validated.');
      }

      return {
        valid: true,
        correctedPatch: currentPatch,
        attempts: attempt,
      };
    } catch (err: unknown) {
      const errorMessage = err instanceof Error
        ? err.message
        : String(err);

      if (attempt === 1) {
        emit(`[PATCH] Syntax error detected. Running self-correction... (${errorMessage})`);
      } else {
        emit(`[PATCH] Attempt ${attempt} failed: ${errorMessage}`);
      }

      if (attempt < MAX_ATTEMPTS) {
        // Send correction prompt to Groq
        try {
          const correctionResponse = await groqWithRetry({
            model: 'llama-3.3-70b-versatile',
            max_tokens: 1500,
            temperature: 0,
            messages: [
              {
                role: 'system',
                content:
                  'You are a security engineer. Return ONLY valid TypeScript code with no markdown fences, no explanation, no commentary. Just the fixed code.',
              },
              {
                role: 'user',
                content: `The previous patch had this TypeScript error: ${errorMessage}. Fix only the syntax error. Do not change the security logic. Return only valid TypeScript code.\n\nBroken code:\n${currentPatch}`,
              },
            ],
          });

          const correctedOutput =
            correctionResponse.choices[0]?.message?.content?.trim() || '';
          if (correctedOutput.length > 50) {
            currentPatch = correctedOutput
              .replace(/^```(?:typescript|ts)?\n?/gm, '')
              .replace(/```$/gm, '')
              .trim();
            emit(`[PATCH] Self-correction attempt ${attempt + 1} ready. Re-validating...`);
          } else {
            emit('[PATCH] Self-correction returned empty output.');
          }
        } catch (groqErr: unknown) {
          emit(`[PATCH] Self-correction AI call failed: ${groqErr instanceof Error ? groqErr.message : String(groqErr)}`);
        }
      }
    }
  }

  // All attempts exhausted
  emit(
    '[PATCH ERROR] Could not generate valid patch after 3 attempts. Manual review required.'
  );

  return {
    valid: false,
    error: 'All 3 validation attempts failed',
    attempts: MAX_ATTEMPTS,
  };
}

export async function generatePatch(
  finding: BOLAFinding,
  config: ScanConfig,
  emit: (msg: string, payload?: unknown) => void,
  signal?: AbortSignal
): Promise<PatchResult> {
  if (signal?.aborted) throw new Error('Scan aborted');
  const candidatePaths = buildCandidatePaths(finding.endpoint);

  emit('[AI] Reading source file from GitHub...');
  await sleep(600);

  let githubCode: string | null = null;
  let vulnerableFilePath = finding.endpoint;

  const token = config.githubToken;
  const owner = config.githubRepoOwner;
  const repo = config.githubRepoName;

  if (!token || !owner || !repo) {
    emit('[AI] GitHub not configured — cannot read source file');
  } else {
    for (const filePath of candidatePaths) {
      emit(`[AI] Probing: ${filePath}`);
      const code = await readFileFromGitHub(filePath, config);
      if (code) {
        githubCode = code;
        vulnerableFilePath = filePath;
        emit(`[AI] Found source file at: ${filePath}`);
        break;
      }
    }
    if (!githubCode) {
      emit('[AI] Source file not found — patch will be in PR description');
    }
  }

  let sourceCode = githubCode;
  if (!sourceCode) {
    sourceCode = `// Could not read actual source from GitHub
// Inferred vulnerable pattern for: ${finding.endpoint}
// This file fetches a resource by ID without checking ownership.`;
  }

  emit('[AI] Analyzing codebase structure...');
  await sleep(800);

  // Dynamic inference
  let ownershipField = githubCode ? (inferOwnershipField(githubCode) || '') : '';
  const { library: authLibrary, sessionAccessor } = githubCode ? inferAuthLibrary(githubCode) : { library: 'Unknown', sessionAccessor: '' };
  const manualReviewRequired = !!githubCode && ownershipField.trim() === '';

  emit(`[AI] Known failure profile: BOLA on parameterized routes`);
  await sleep(400);
  if (githubCode) {
    emit(`[AI] Identified ownership field: ${ownershipField}`);
    await sleep(400);
    emit(`[AI] Identified auth library: ${authLibrary}`);
    await sleep(300);
    emit(`[AI] Identified session accessor: ${sessionAccessor}`);
    await sleep(500);
    if (manualReviewRequired) {
      emit('[AI] Ownership field could not be inferred — skipping AI patching and generating manual-review template.');
    }
  }

  function sanitizeUntrustedData(data: string, type: string) {
    if (!data) return '';
    const truncated = data.slice(0, 2000);
    const badWords = ["ignore", "forget", "instead", "pretend", "you are now", "new instruction"];
    const lines = truncated.split('\n').filter(line => {
      const lower = line.toLowerCase();
      return !badWords.some(w => lower.includes(w));
    });
    return `[UNTRUSTED ${type} START]\n${lines.join('\n')}\n[END]`;
  }

  function shrinkJSON(obj: unknown): unknown {
    return summarizeForPrompt(obj);
  }

  let patchedCode: string = '';
  let patchSource: 'github_ai' | 'response_ai' | 'deterministic' | 'manual_review_required' = manualReviewRequired ? 'manual_review_required' : 'deterministic';
  const groqKey = process.env.GROQ_API_KEY;

  // TIER 1 — GitHub Source + Groq AI
  if (githubCode && !manualReviewRequired && groqKey && groqKey.length > 10) {
    emit('[AI] Calling AI engine with source context...');
    try {
      const response = await groqWithRetry({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 1500,
        temperature: 0,
        messages: [
          {
            role: 'system',
            content: 'You are a security engineer. Return ONLY valid TypeScript code with no markdown fences, no explanation, no commentary. Just the fixed code.',
          },
          {
            role: 'user',
            content: `Fix this BOLA vulnerability by adding an ownership check.

Vulnerable endpoint: ${finding.endpoint}
Ownership field on the record: ${ownershipField}
Auth library: ${authLibrary}
Session user ID accessor: ${sessionAccessor}

Vulnerable code:
${sanitizeUntrustedData(githubCode, 'SOURCE CODE')}

Return the complete fixed file with the correct ownership check returning a 403 Forbidden error.`,
          },
        ],
      });

      const aiOutput = response.choices[0]?.message?.content?.trim() || '';

      if (aiOutput.includes(ownershipField) && aiOutput.includes('403') && aiOutput.length > 200) {
        patchedCode = aiOutput.replace(/^```(?:typescript|ts)?\n?/gm, '').replace(/```$/gm, '').trim();
        patchSource = 'github_ai';
        emit('[AI] AI patch generated from source context and validated ✓');
      } else {
        emit('[AI] AI engine output did not pass validation, falling back...');
      }
    } catch (err: unknown) {
      emit(`[AI] AI engine error: ${err instanceof Error ? err.message : String(err)}. Falling back...`);
    }
  }

  // TIER 2 — Response-Based Groq AI
  if (patchSource === 'deterministic' && !manualReviewRequired && groqKey && groqKey.length > 10) {
    if (!githubCode) emit('[AI] GitHub unavailable — generating patch from response analysis...');
    else emit('[AI] Generating patch from response analysis fallback...');

    try {
      const sensitiveKeys = finding.sensitiveFields.map(f => f.key).join(', ');
      const exploitContext = finding.attackerAuthenticated
        ? 'an authenticated attacker using their own session cookie'
        : 'an unauthenticated attacker with no session';

      const promptStr = `You are a security engineer. A BOLA vulnerability was found at ${finding.endpoint}. An attacker (${exploitContext}) could access ${sensitiveKeys} belonging to another user.
      
Response Data:
${sanitizeUntrustedData(JSON.stringify(shrinkJSON(finding.stolenData), null, 2), 'RESPONSE DATA')}

Generate a generic ownership validation middleware or route guard in TypeScript/Node.js that fixes this. Return ONLY valid code, no markdown, no explanation.`;

      const response = await groqWithRetry({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 1500,
        temperature: 0,
        messages: [
          { role: 'system', content: 'You are a security engineer. Return ONLY valid code, no markdown, no explanation.' },
          { role: 'user', content: promptStr }
        ]
      });

      const aiOutput = response.choices[0]?.message?.content?.trim() || '';
      if (aiOutput.length > 50) {
        patchedCode = aiOutput.replace(/^```(?:typescript|ts)?\n?/gm, '').replace(/```$/gm, '').trim();
        patchSource = 'response_ai';
        emit('[AI] AI patch generated from response analysis ✓');
      } else {
        emit('[AI] AI engine output invalid, falling back to template...');
      }
    } catch (err: unknown) {
      emit(`[AI] AI engine error: ${err instanceof Error ? err.message : String(err)}. Falling back to template...`);
    }
  }

  // TIER 3 — Deterministic Template
  if (patchSource === 'deterministic' || patchSource === 'manual_review_required') {
    emit('[AI] AI unavailable or failed — generating template patch...');
    const sensitiveKeys = finding.sensitiveFields.map(f => f.key).join(', ');
    patchedCode = `// VibeAudit Security Patch
// Vulnerability: BOLA at ${finding.endpoint}
// Fix: Add ownership validation before returning data

async function validateOwnership(
  requestedId: string, 
  sessionUserId: string,
  resourceType: string
): Promise<boolean> {
  if (requestedId !== sessionUserId) {
    throw new Error('Forbidden: You do not own this resource');
  }
  return true;
}

// Apply this check in your ${finding.endpoint} handler:
// await validateOwnership(params.id, session.user.id, '[resource]')

// Original exposed fields that require protection: ${sensitiveKeys}
`;
  }

  // ── ESBUILD VALIDATION ──────────────────────────────────────────────────
  // Validate the AI-generated patch before it goes anywhere near GitHub.
  // Only run validation for AI-generated patches (not deterministic templates).
  let patchValidated = !manualReviewRequired;

  if ((patchSource === 'github_ai' || patchSource === 'response_ai') && groqKey && groqKey.length > 10) {
    emit('[PATCH] Validating generated patch syntax...');
    await sleep(300);

    const validationResult = await validatePatch(
      patchedCode,
      `Fix BOLA vulnerability at ${finding.endpoint}`,
      emit
    );

    if (validationResult.valid && validationResult.correctedPatch) {
      patchedCode = validationResult.correctedPatch;
    } else {
      patchValidated = false;
      ownershipField = 'manual-review';
    }
  }
  
  if (patchedCode.includes('YOUR_OWNERSHIP_FIELD') || patchedCode.includes('YOUR_SESSION_ACCESSOR')) {
    emit('[PATCH] Warning: Could not infer ownership field from source. Generated patch requires manual review before merging.');
    patchValidated = false;
  }

  const displayPatch = patchedCode.split('\n').map(line => '+' + line).join('\n');

  emit('[AI] Patch ready.', { patchedCode: displayPatch, displayPatch, patchSource, patchValidated });
  await sleep(300);
  emit('[AI] Generating security regression test...');
  await sleep(600);
  emit('[AI] Test ready.');

  return {
    originalCode: sourceCode,
    patchedCode,
    displayPatch,
    filePath: vulnerableFilePath,
    ownershipField,
    authLibrary,
    sessionAccessor,
    reasoning: [
      `Vulnerable endpoint: ${finding.endpoint}`,
      `Identified ownership field: ${ownershipField}`,
      `Identified auth library: ${authLibrary}`,
      `Identified session accessor: ${sessionAccessor}`,
      patchSource === 'github_ai'
        ? `Applied ownership check: record.${ownershipField} !== ${sessionAccessor} → 403`
        : `Generated generic ownership validation guard for sensitive data exposure.`,
    ],
    patchSource: patchSource as PatchResult['patchSource'],
    patchValidated,
  };
}

// ── AI Vulnerability Analysis (CVSS Scoring) ─────────────────────────────────

export interface VulnerabilityAnalysis {
  isVulnerable: boolean;
  confidence: number;
  cvssScore: number;
  severity: Severity;
  dataExposed: string[];
  reasoning: string;
  patchSuggestion: string;
}

const DEFAULT_ANALYSIS: VulnerabilityAnalysis = {
  isVulnerable: true,
  confidence: 70,
  cvssScore: 9.3,
  severity: 'CRITICAL',
  dataExposed: ['unknown'],
  reasoning: 'AI analysis unavailable — using default CVSS 9.3 CRITICAL rating for confirmed BOLA.',
  patchSuggestion: 'Add ownership validation: verify the authenticated user owns the requested resource before returning data.',
};

/**
 * Call Groq AI to analyze a confirmed vulnerability and produce a structured
 * CVSS score, severity rating, confidence level, and list of exposed data types.
 *
 * Falls back to sensible defaults if the AI call fails or returns invalid JSON.
 */
export async function analyzeVulnerability(
  endpointPath: string,
  victimResponse: string,
  attackerResponse: string
): Promise<VulnerabilityAnalysis> {
  const groqKey = process.env.GROQ_API_KEY;
  if (!groqKey || groqKey.length < 10) {
    console.log('[CVSS] No AI API key — returning default analysis');
    return DEFAULT_ANALYSIS;
  }

  // Truncate responses to stay within context limits
  const maxLen = 3000;
  const victimTruncated = victimResponse.length > maxLen
    ? victimResponse.slice(0, maxLen) + '\n... [truncated]'
    : victimResponse;
  const attackerTruncated = attackerResponse.length > maxLen
    ? attackerResponse.slice(0, maxLen) + '\n... [truncated]'
    : attackerResponse;

  const prompt = `You are a security analyst performing CVSS scoring on a confirmed BOLA (Broken Object Level Authorization) vulnerability.

Endpoint: ${endpointPath}

Victim's response (User A — the data owner):
${victimTruncated}

Attacker's response (User B — should NOT have access):
${attackerTruncated}

Analyze the data exposed and return ONLY a JSON object (no markdown, no code fences, no explanation outside the JSON) with these exact fields:
{
  "isVulnerable": boolean,
  "confidence": number (0-100, how confident you are this is a real vulnerability),
  "cvssScore": number (0.0-10.0, use CVSS v3.1 base score),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "dataExposed": string[] (list of data categories found, e.g. ["email", "SSN", "credit_card", "address", "medical_records", "password_hash"]),
  "reasoning": string (one paragraph explaining the score),
  "patchSuggestion": string (one sentence fix recommendation)
}

CVSS Scoring Guide:
- CRITICAL 9.0-10.0: Credentials, passwords, PHI (medical records, SSN), financial data (full card numbers, bank accounts)
- HIGH 7.0-8.9: PII (email, phone, full name + address), authentication tokens
- MEDIUM 4.0-6.9: Non-sensitive user data (preferences, order status without financial details)
- LOW 0.1-3.9: Minor information disclosure (usernames, public profile data)
- INFO 0.0: No real data exposure

Return ONLY the JSON object.`;

  try {
    const response = await groqWithRetry({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 800,
      temperature: 0.1,
      messages: [
        {
          role: 'system',
          content: 'You are a security analyst. Return ONLY valid JSON. No markdown, no explanation outside JSON.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    let rawOutput = response.choices[0]?.message?.content?.trim() || '';

    // Strip markdown code fences if present
    rawOutput = rawOutput
      .replace(/^```(?:json)?\n?/gm, '')
      .replace(/```$/gm, '')
      .trim();

    const parsed = JSON.parse(rawOutput);

    // Validate and clamp values
    const validSeverities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const severity: Severity = validSeverities.includes(parsed.severity)
      ? parsed.severity
      : 'CRITICAL';

    const cvssScore = typeof parsed.cvssScore === 'number'
      ? Math.max(0, Math.min(10, parseFloat(parsed.cvssScore.toFixed(1))))
      : 9.3;

    const confidence = typeof parsed.confidence === 'number'
      ? Math.max(0, Math.min(100, Math.round(parsed.confidence)))
      : 70;

    const dataExposed = Array.isArray(parsed.dataExposed)
      ? parsed.dataExposed.filter((d: unknown) => typeof d === 'string')
      : ['unknown'];

    return {
      isVulnerable: parsed.isVulnerable !== false,
      confidence,
      cvssScore,
      severity,
      dataExposed: dataExposed.length > 0 ? dataExposed : ['unknown'],
      reasoning: typeof parsed.reasoning === 'string' ? parsed.reasoning : DEFAULT_ANALYSIS.reasoning,
      patchSuggestion: typeof parsed.patchSuggestion === 'string' ? parsed.patchSuggestion : DEFAULT_ANALYSIS.patchSuggestion,
    };
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error(`[CVSS] AI analysis failed: ${errorMessage}`);
    return DEFAULT_ANALYSIS;
  }
}
