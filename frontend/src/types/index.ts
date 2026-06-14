// NOTE: Core types here mirror scanner/src/types.ts.
// Single source of truth is scanner/src/types.ts.
// If scanner types change, update this file too.

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
  loginPath?: string;
  pagesToCrawl?: string[];
  loginFieldSelectors?: LoginFieldSelectors;
  authType?: 'cookie' | 'jwt' | 'auto';
  githubRepoOwner?: string;
  githubRepoName?: string;
  githubBaseBranch?: string;
  githubToken?: string;
}

export interface DiscoveredEndpoint {
  method: string;
  url: string;
  path: string;
  statusCode: number;
  isAuthenticated: boolean;
  authMethod: 'cookie' | 'jwt' | 'unknown';
  requestHeaders: Record<string, string>;
  timestamp: number;
}

export interface SensitiveField {
  key: string;
  value: unknown;
  category: 'PII' | 'PHI' | 'FINANCIAL' | 'AUTH' | 'UNKNOWN';
}

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
  confidenceScore: number;
}

export interface BOLAResult {
  finding: BOLAFinding | null;
  reason: 'vulnerable' | 'no_candidates' | 'not_exploitable' | 'blocked' | 'inconclusive';
}

export interface PatchResult {
  originalCode: string;
  patchedCode: string;
  displayPatch: string;
  filePath: string;
  ownershipField: string;
  authLibrary: string;
  sessionAccessor: string;
  reasoning: string[];
  patchSource: 'github_ai' | 'response_ai' | 'deterministic';
  patchValidated?: boolean | null;
  prUrl?: string;
}

export type SSEStage = 'preflight' | 'crawler' | 'attack' | 'ai' | 'github' | 'verify' | 'done' | 'summary' | 'complete';
export type SSEType = 'log' | 'endpoint' | 'finding' | 'data' | 'patch' | 'complete' | 'error' | 'result' | 'clean' | 'testing' | 'vulnerable' | 'safe';

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
  // Summary fields
  endpointsFound?: number;
  vulnerabilities?: number;
  attacksAttempted?: number;
  targetUrl?: string;
  scanDurationMs?: number;
  timeToExploitMs?: number | null;
  [key: string]: any; // Allow arbitrary stats objects passed in summary
}

export type SeverityLabel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';

export function getSeverity(confidence: number | null): { score: number; label: SeverityLabel } {
  if (!confidence) return { score: 0, label: 'CLEAN' };
  if (confidence >= 90) return { score: 8.9, label: 'CRITICAL' };
  if (confidence >= 70) return { score: 7.2, label: 'HIGH' };
  if (confidence >= 50) return { score: 5.5, label: 'MEDIUM' };
  return { score: 3.1, label: 'LOW' };
}

export interface ScanHistoryEntry {
  id: string;
  timestamp: number;
  status: 'vulnerable' | 'clean' | 'blocked' | 'error';
  endpoint?: string | null;
  confidenceScore?: number | null;
  sensitiveFields?: string[];
  patch?: string | null;
  prUrl?: string | null;
}

export interface ScanMeta {
  scanId: string;
  startTime: number;
  endTime: number;
  endpointsDiscovered: number | null;
  endpointsTested: number | null;
  scannerVersion: string;
  aiModel: string;
  prUrl: string | null;
  prGenerationAttempted?: boolean | null;
  prGenerationSkippedReason?: string | null;
  githubRepoOwner?: string | null;
  githubRepoName?: string | null;
  patchValidated?: boolean | null;
  patchGenerationAttempted?: boolean | null;
  patchGenerationSkippedReason?: string | null;
  testedEndpoints?: string[];
  
  // Dashboard Metrics
  discoveryStats?: {
    pagesVisited: number | null;
    totalEndpoints: number | null;
    uniqueEndpoints: number | null;
    parameterizedEndpoints: number | null;
    bolaCandidates: number | null;
  };
  replayStats?: {
    eligible: number | null;
    tested: number | null;
    skipped: number | null;
  };
  skipReasons?: {
    missingObjectId: number;
    authReplayFailed: number;
    noSecondUser: number;
    unsupportedRoute: number;
    parseFailure: number;
    other: number;
  };
  confirmationStats?: {
    candidates: number | null;
    rejected: number | null;
    confirmed: number | null;
  };
  rejectionReasons?: {
    returned403: number;
    returned404: number;
    responseMismatch: number;
    insufficientEvidence: number;
    diffSimilarityTooLow: number;
    other: number;
  };
  remediationStats?: {
    attempted: boolean | null;
    generated: boolean | null;
    skipped: boolean | null;
    validated: boolean | null;
    validationFailed: boolean | null;
    codeContextConfidence: string | null;
    patchSkippedReason: string | null;
  };
  githubStats?: {
    repoProvided: boolean;
    tokenProvided: boolean;
    attempted: boolean | null;
    created: boolean | null;
    skipped: boolean | null;
    prUrl: string | null;
    prSkippedReason: string | null;
  };
}

export interface ReportData {
  scanConfig: ScanConfig;
  finding: BOLAFinding;
  patch: PatchResult;
  regressionTest: string;
  scanMeta: ScanMeta;
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
