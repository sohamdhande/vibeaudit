// NOTE: Core types here are duplicated in 
// frontend/src/types/index.ts by design.
// Single source of truth is scanner/src/types.ts.
// If you change a type here, update frontend too.
// Future: extract to shared/types package.

export interface UserCredentials {
  email: string;
  password: string;
}

export interface LoginFieldSelectors {
  email?: string;
  password?: string;
  submit?: string;
}

export interface ScanConfig {
  targetUrl: string;
  userA: UserCredentials;
  userB: UserCredentials;
  loginPath?: string;           // default: '/login'
  pagesToCrawl?: string[];      // default: ['/dashboard']
  loginFieldSelectors?: LoginFieldSelectors;
  authType?: 'cookie' | 'jwt' | 'auto';
  githubToken?: string;
  githubRepoOwner?: string;
  githubRepoName?: string;
  githubBaseBranch?: string;
}

export interface DiscoveredEndpoint {
  method: string;
  url: string;
  path: string;
  statusCode: number;
  isAuthenticated: boolean;
  authMethod: 'cookie' | 'jwt' | 'unknown';
  requestHeaders: Record<string, string>;
  requestBody?: string;
  timestamp: number;
}

export interface SensitiveField {
  key: string;
  value: unknown;
  category: 'PII' | 'PHI' | 'FINANCIAL' | 'AUTH' | 'UNKNOWN';
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface BOLAFinding {
  endpoint: string;
  method: string;
  victimToken: string;
  attackerToken: string;
  victimResourceId: string;
  stolenData: Record<string, unknown>;
  sensitiveFields: SensitiveField[];
  attackerAuthenticated: boolean;
  curlReproduction: string;
  cvssScore: number;
  severity: Severity;
  confidenceScore: number;
  dataExposed: string[];
}

export interface BOLAResult {
  finding: BOLAFinding | null;
  reason: 'vulnerable' | 'blocked' | 'not_exploitable' | 'inconclusive' | 'no_candidates';
  attackStats?: {
    replay: {
      eligible: number | null;
      tested: number | null;
      skipped: number | null;
    };
    skipReasons: {
      missingObjectId: number;
      authReplayFailed: number;
      noSecondUser: number;
      unsupportedRoute: number;
      parseFailure: number;
      other: number;
    };
    confirmation: {
      candidates: number | null;
      rejected: number | null;
      confirmed: number | null;
    };
    rejectionReasons: {
      returned403: number;
      returned404: number;
      responseMismatch: number;
      insufficientEvidence: number;
      diffSimilarityTooLow: number;
      other: number;
    };
  };
}

export interface PatchResult {
  originalCode: string;
  patchedCode: string;
  displayPatch: string;
  filePath: string;
  ownershipField: string | null;
  authLibrary: string | null;
  sessionAccessor: string | null;
  reasoning: string[];
  patchSource: 'github_ai' | 'response_ai' | 'deterministic' | 'skipped';
  patchValidated: boolean;
  patchGenerationAttempted?: boolean;
  patchGenerationSkippedReason?: string | null;
}

export interface ScanResult {
  targetUrl: string;
  endpoints: DiscoveredEndpoint[];
  bolaFinding: BOLAFinding | null;
  patch: PatchResult | null;
  playwrightTest: string | null;
  prUrl: string | null;
  verificationStatus: '403_confirmed' | 'patch_failed' | 'not_run';
}

export type SSEStage = 'preflight' | 'crawler' | 'attack' | 'ai' | 'github' | 'verify' | 'done' | 'complete' | 'summary';
export type SSEType = 'log' | 'endpoint' | 'finding' | 'data' | 'patch' | 'complete' | 'error' | 'clean' | 'result' | 'testing' | 'vulnerable' | 'safe';

export interface SSEPayload {
  scanId?: string;
  endpoint?: string;
  url?: string;
  sensitiveFields?: unknown[];
  confidenceScore?: number;
  patch?: string;
  patchedCode?: string;
  code?: string;
  patchSource?: 'github_ai' | 'response_ai' | 'deterministic' | null;
  regressionTest?: string;
  testCode?: string;
  prUrl?: string;
  verificationResult?: 'blocked' | 'pending' | null;
  reason?: string;
  summary?: ScanSummary;
  [key: string]: unknown;
}

export interface SSEEvent {
  stage: SSEStage;
  type: SSEType;
  message: string;
  payload?: SSEPayload;
  timestamp: number;
  endpointsFound?: number;
  vulnerabilities?: number;
  attacksAttempted?: number;
  targetUrl?: string;
  scanDurationMs?: number;
  timeToExploitMs?: number;
}

export interface CrawlResult {
  targetUrl: string;
  endpoints: DiscoveredEndpoint[];
  crawlDurationMs: number;
  error?: string;
}

export interface ScanSummary {
  meta: {
    scanId: string;
    targetUrl: string;
    status: 'success' | 'failure' | 'cancelled' | 'degraded';
    startTime: number;
    endTime: number;
    durationMs: number;
    scannerVersion: string;
  };
  
  telemetry: {
    discovery: {
      pagesVisited: number | null;
      totalEndpoints: number | null;
      uniqueEndpoints: number | null;
      parameterizedEndpoints: number | null;
      bolaCandidates: number | null;
    };
    replay: {
      eligible: number | null;
      tested: number | null;
      skipped: number | null;
      skipReasons: Record<string, number>;
    };
    confirmation: {
      candidates: number | null;
      confirmed: number | null;
      rejected: number | null;
      rejectionReasons: Record<string, number>;
    };
    remediation: {
      attempted: boolean | null;
      generated: boolean | null;
      skipped: boolean | null;
      validated: boolean | null;
      validationFailed: boolean | null;
      codeContextConfidence: string | null;
      patchSkippedReason: string | null;
    };
    github: {
      repoProvided: boolean;
      tokenProvided: boolean;
      attempted: boolean | null;
      created: boolean | null;
      skipped: boolean | null;
      prUrl: string | null;
      prSkippedReason: string | null;
    };
  };

  results: {
    finding: BOLAFinding | null;
    patch: PatchResult | null;
    regressionTest: string | null;
    prUrl: string | null;
  };
}
