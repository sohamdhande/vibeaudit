import { useState, useCallback, useRef, useEffect } from 'react';
import { ScanConfig, ScanHistoryEntry, SSEEvent, SSEStage, getSeverity } from '../types';



const STORAGE_KEY = 'vibeaudit_active_scan';

const saveActiveScan = (scanId: string) => {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    scanId,
    startedAt: Date.now(),
  }));
};

const clearActiveScan = () => {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
};

const getActiveScan = (): {
  scanId: string;
  startedAt: number;
} | null => {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (Date.now() - parsed.startedAt > 10 * 60 * 1000) {
      clearActiveScan();
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
};

export function useVibeScanner() {
  // Lazy-initialize: if there's an active scan in localStorage, skip 'landing'
  // so the first render already shows the scanning UI (no flash)
  const [activeStage, setActiveStage] = useState<SSEStage | 'landing'>(() => {
    if (typeof window !== 'undefined') {
      try {
        const raw = localStorage.getItem('vibeaudit_active_scan');
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Date.now() - parsed.startedAt <= 10 * 60 * 1000) {
            return 'preflight';
          }
        }
      } catch { /* ignore */ }
    }
    return 'landing';
  });
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [isScanning, setIsScanning] = useState(() => {
    if (typeof window !== 'undefined') {
      try {
        const raw = localStorage.getItem('vibeaudit_active_scan');
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Date.now() - parsed.startedAt <= 10 * 60 * 1000) {
            return true;
          }
        }
      } catch { /* ignore */ }
    }
    return false;
  });
  const [error, setError] = useState<string | null>(null);
  const [isClean, setIsClean] = useState(false);
  const [endpointProgress, setEndpointProgress] = useState<{
    current: string | null;
    method: string | null;
    status: 'testing' | 'vulnerable' | 'safe' | null;
    completed: number;
    total: number;
    log: Array<{ endpoint: string; method: string; status: 'testing' | 'vulnerable' | 'safe'; timestamp: number }>;
  }>({
    current: null,
    method: null,
    status: null,
    completed: 0,
    total: 0,
    log: [],
  });
  
  const abortControllerRef = useRef<AbortController | null>(null);
  const eventBufferRef = useRef<SSEEvent[]>([]);
  const flushTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const retryTimerRef = useRef<NodeJS.Timeout | null>(null);
  const scanConfigRef = useRef<ScanConfig | null>(null);
  const currentScanIdRef = useRef<string | null>(null);
  const currentSessionTokenRef = useRef(0);
  const reconnectAttemptsRef = useRef<number>(0);

  // Accumulated data across SSE events for history
  const accumulatedFinding = useRef<{
    endpoint: string | null;
    sensitiveFields: string[];
    confidenceScore: number | null;
    patch: string | null;
    patchSource: string | null;
    regressionTest: string | null;
    prUrl: string | null;
    exploitConfirmedAt: number | null;
    verificationResult: 'blocked' | 'pending' | null;
    curlReproduction: string | null;
    victimResourceId: string | null;
    method: string | null;
  }>({
    endpoint: null,
    sensitiveFields: [],
    confidenceScore: null,
    patch: null,
    patchSource: null,
    regressionTest: null,
    prUrl: null,
    exploitConfirmedAt: null,
    verificationResult: null,
    curlReproduction: null,
    victimResourceId: null,
    method: null,
  });

  // Flush buffer to state
  const flushBuffer = useCallback(() => {
    if (eventBufferRef.current.length > 0) {
      const newEvents = [...eventBufferRef.current];
      eventBufferRef.current = [];
      
      setEvents(prev => [...prev, ...newEvents]);

      // Update stage if the last event has a new stage
      const lastEvent = newEvents[newEvents.length - 1];
      setActiveStage(current => {
        if (current === 'summary' && lastEvent.stage !== 'summary') return current;
        if (current !== lastEvent.stage) {
          return lastEvent.stage;
        }
        return current;
      });
    }
  }, []);

  // Shared SSE event handler used by both new scans and reconnections
  const handleSSEEvent = useCallback((event: SSEEvent, sessionToken?: number) => {
    if (sessionToken !== undefined && sessionToken !== currentSessionTokenRef.current) return;

    // Capture scanId from first preflight event
    if (event.payload && event.payload.scanId && !currentScanIdRef.current) {
      currentScanIdRef.current = event.payload.scanId;
      saveActiveScan(event.payload.scanId);
    }

    eventBufferRef.current.push(event);

    // If we get a complete clean event, transition to victory stage
    if (event.stage === 'complete' && event.type === 'clean') {
      setIsClean(true);
      setActiveStage('summary');
      clearActiveScan();
    } else if (event.stage === 'done' && event.type === 'complete') {
      setActiveStage('summary');
      clearActiveScan();
    } else if (event.stage === 'done' && event.type === 'error') {
      clearActiveScan();
    }

    const acc = accumulatedFinding.current;

    // Generic extraction from payload
    if (event.payload && typeof event.payload === 'object') {
      if (event.payload.endpoint || event.payload.url) {
        acc.endpoint = event.payload.endpoint || event.payload.url || null;
      }
      if (event.payload.sensitiveFields && Array.isArray(event.payload.sensitiveFields)) {
        const fields = event.payload.sensitiveFields.map((f: unknown) =>
          typeof f === 'string' ? f : (f as {key?: string})?.key || String(f)
        );
        acc.sensitiveFields = [...new Set([...acc.sensitiveFields, ...fields])];
      }
      if (event.payload.confidenceScore !== undefined) {
        acc.confidenceScore = event.payload.confidenceScore;
      }
      if (event.payload.patch || event.payload.patchedCode || event.payload.code) {
        acc.patch = event.payload.patchedCode || event.payload.patch || event.payload.code || null;
      }
      if (event.payload.patchSource) {
        acc.patchSource = event.payload.patchSource;
      }
      if (event.payload.regressionTest || event.payload.testCode) {
        acc.regressionTest = event.payload.regressionTest || event.payload.testCode || null;
      }
      if (event.payload.prUrl) {
        acc.prUrl = event.payload.prUrl;
      }
    }

    // Stage-specific manual overrides just in case
    if (event.stage === 'attack' && event.type === 'finding') {
      acc.exploitConfirmedAt = Date.now();
      if (event.payload?.curlReproduction) acc.curlReproduction = event.payload.curlReproduction as string;
      if (event.payload?.victimResourceId) acc.victimResourceId = event.payload.victimResourceId as string;
      if (event.payload?.method) acc.method = event.payload.method as string;
    }

    // Per-endpoint progress tracking
    if (event.stage === 'attack' && (event.type === 'testing' || event.type === 'vulnerable' || event.type === 'safe')) {
      const ep = (event.payload?.endpoint as string) || '';
      const method = (event.payload?.method as string) || '';
      const completed = (event.payload?.completed as number) ?? 0;
      const total = (event.payload?.total as number) ?? 0;
      setEndpointProgress(prev => ({
        current: ep,
        method,
        status: event.type as 'testing' | 'vulnerable' | 'safe',
        completed,
        total,
        log: [...prev.log, { endpoint: ep, method, status: event.type as 'testing' | 'vulnerable' | 'safe', timestamp: event.timestamp }],
      }));
    }

    // Save to scan history on summary event
    if ((event.stage as string) === 'summary' && (event.type as string) === 'result' && scanConfigRef.current) {
      try {
        const vuln = (event.vulnerabilities ?? 0) > 0;
        // Prefer fields from the summary event payload first, fallback to accumulated state
        const endpoint = event.payload?.endpoint || acc.endpoint;
        const confidence = event.payload?.confidenceScore ?? acc.confidenceScore;
        let fields = acc.sensitiveFields;
        if (event.payload?.sensitiveFields && Array.isArray(event.payload.sensitiveFields)) {
          fields = event.payload.sensitiveFields as string[];
        }
        const patch = event.payload?.patch || acc.patch;
        const patchSource = event.payload?.patchSource || acc.patchSource;
        const regressionTest = event.payload?.regressionTest || acc.regressionTest;
        const prUrl = event.payload?.prUrl || acc.prUrl;

        if (vuln) {
          getSeverity(confidence ?? 75);
        }

        console.log('[HISTORY] Building entry:', { vuln, confidence, endpoint, fields, patch: !!patch });

        const entry: ScanHistoryEntry = {
          id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          timestamp: Date.now(),
          status: vuln ? 'vulnerable' : 'clean',
          endpoint: endpoint || null,
          confidenceScore: confidence || null,
          sensitiveFields: fields || [],
          patch: patch || null,
          prUrl: prUrl || null,
        };
        const existing: ScanHistoryEntry[] = JSON.parse(localStorage.getItem('vibeaudit_history') || '[]');
        const updated = [entry, ...existing].slice(0, 10);
        localStorage.setItem('vibeaudit_history', JSON.stringify(updated));
        console.log('[HISTORY] Saved entry:', entry.id);

        if (vuln) {
          try {
            // Strip Cookie headers from curlReproduction
            let safeCurl = acc.curlReproduction || '';
            safeCurl = safeCurl.replace(/(Cookie|Authorization|X-Auth-Token):\s*\S+/gi, '$1: [REDACTED]');
            
            console.log('[VibeAudit] patch object keys:', patch ? Object.keys(patch) : 'patch is null');
            console.log('[VibeAudit] displayPatch value:', (patch as unknown as Record<string, unknown>)?.displayPatch || (patch as unknown as Record<string, unknown>)?.display_patch || (patch as unknown as Record<string, unknown>)?.diff || (typeof patch === 'string' ? 'is string' : 'MISSING'));
            
            // Build ReportData blob
            const reportData = {
              scanConfig: {
                targetUrl: scanConfigRef.current?.targetUrl || 'Unknown',
                userA: { email: '', password: '' },
                userB: { email: '', password: '' }
              },
              finding: {
                endpoint: endpoint || 'Unknown',
                method: acc.method || 'GET',
                victimToken: '[REDACTED]',
                attackerToken: '[REDACTED]',
                victimResourceId: acc.victimResourceId || '',
                stolenData: {},
                sensitiveFields: fields.map(f => ({ key: f, value: '[REDACTED]', category: 'UNKNOWN' as const })),
                attackerAuthenticated: true,
                curlReproduction: safeCurl,
                cvssScore: confidence && confidence >= 90 ? 8.9 : 7.2,
                confidenceScore: confidence || 0,
              },
              patch: {
                displayPatch: (patch as unknown as Record<string, unknown>)?.displayPatch as string || (patch as unknown as Record<string, unknown>)?.display_patch as string || (patch as unknown as Record<string, unknown>)?.diff as string || (typeof patch === 'string' ? patch : ''),
                filePath: (patch as unknown as Record<string, unknown>)?.filePath as string || (patch as unknown as Record<string, unknown>)?.file_path as string || 'unknown',
                explanation: (patch as unknown as Record<string, unknown>)?.explanation as string || null,
                ownershipField: (patch as unknown as Record<string, unknown>)?.ownershipField as string || (patch as unknown as Record<string, unknown>)?.ownership_field as string || null,
                authLibrary: (patch as unknown as Record<string, unknown>)?.authLibrary as string || (patch as unknown as Record<string, unknown>)?.auth_library as string || null,
                originalCode: '',
                patchedCode: '',
                sessionAccessor: 'req.user.id',
                reasoning: (patch as unknown as Record<string, unknown>)?.reasoning as string[] || [],
                patchSource: patchSource || 'response_ai',
              },
              regressionTest: regressionTest || '// No regression test available',
              scanMeta: {
                scanId: entry.id,
                startTime: Date.now(),
                endTime: Date.now(),
                endpointsDiscovered: event.endpointsFound || 0,
                endpointsTested: event.attacksAttempted || 0,
                scannerVersion: '1.0.0',
                aiModel: 'AI-powered analysis',
                prUrl: prUrl || null,
              }
            };
            
            // Cleanup old blobs (keep last 5)
            const keys = Object.keys(localStorage).filter(k => k.startsWith('vibeaudit_report_'));
            if (keys.length >= 5) {
              const sortedKeys = keys.sort((a, b) => {
                const itemA = localStorage.getItem(a);
                const itemB = localStorage.getItem(b);
                const tA = itemA ? JSON.parse(itemA).scanMeta?.startTime : 0;
                const tB = itemB ? JSON.parse(itemB).scanMeta?.startTime : 0;
                return tA - tB;
              });
              for (let i = 0; i <= keys.length - 5; i++) {
                localStorage.removeItem(sortedKeys[i]);
              }
            }
            localStorage.setItem(`vibeaudit_report_${entry.id}`, JSON.stringify(reportData));
          } catch (e) {
            console.error('[HISTORY] Failed to save report data', e);
          }
        }
      } catch (histErr) {
        console.error('[HISTORY] Failed to save:', histErr);
      }
    }

    // Schedule a flush if not already scheduled
    if (!flushTimeoutRef.current) {
      flushTimeoutRef.current = setTimeout(() => {
        flushBuffer();
        flushTimeoutRef.current = null;
      }, 50); // Flush every 50ms to maintain 20fps for high-freq logs
    }
  }, [flushBuffer]);

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort();
      if (flushTimeoutRef.current) {
        clearTimeout(flushTimeoutRef.current);
        flushTimeoutRef.current = null;
      }
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
    };
  }, []);

  const callbacksRef = useRef({ setIsScanning, setActiveStage, handleSSEEvent, flushBuffer, clearActiveScan, setError });
  useEffect(() => {
    callbacksRef.current = { setIsScanning, setActiveStage, handleSSEEvent, flushBuffer, clearActiveScan, setError };
  }, [setIsScanning, setActiveStage, handleSSEEvent, flushBuffer, setError]);

  // On mount, check for an active scan and reconnect
  useEffect(() => {
    const active = getActiveScan();
    if (!active) return;

    // There's a scan in progress — reconnect
    callbacksRef.current.setIsScanning(true);
    callbacksRef.current.setActiveStage('preflight');
    const sessionToken = Date.now();
    currentSessionTokenRef.current = sessionToken;

    const url = `/api/scan/${active.scanId}/stream`;
    abortControllerRef.current = new AbortController();

    reconnectAttemptsRef.current = 0;

    const connect = () => {
      fetch(url, {
        signal: abortControllerRef.current?.signal
      }).then(async (response) => {
        if (!response.ok) throw new Error('Reconnect failed');
        const reader = response.body?.getReader();
        const decoder = new TextDecoder();
        if (!reader) return;
        let buffer = '';
        let terminalEventSeen = false;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const dataStr = line.replace('data: ', '').trim();
              if (dataStr) {
                try {
                  const event = JSON.parse(dataStr) as SSEEvent;
                  reconnectAttemptsRef.current = 0;
                  terminalEventSeen =
                    terminalEventSeen ||
                    event.stage === 'summary' ||
                    event.stage === 'complete' ||
                    (event.stage === 'done' && (event.type === 'complete' || event.type === 'error'));
                  callbacksRef.current.handleSSEEvent(event, sessionToken);
                } catch {}
              }
            }
          }
        }
        if (flushTimeoutRef.current) clearTimeout(flushTimeoutRef.current);
        callbacksRef.current.flushBuffer();
        if (sessionToken === currentSessionTokenRef.current && terminalEventSeen) {
          callbacksRef.current.setIsScanning(false);
        }
      }).catch((err) => {
        if (err.name === 'AbortError') return;
        if (sessionToken !== currentSessionTokenRef.current) return;
        if (reconnectAttemptsRef.current < 5) {
          reconnectAttemptsRef.current++;
          callbacksRef.current.handleSSEEvent({ stage: 'preflight', type: 'log', message: `[SYSTEM] Reconnecting... (${reconnectAttemptsRef.current}/5)`, timestamp: Date.now() }, sessionToken);
          const baseDelay = Math.min(1000 * Math.pow(2, reconnectAttemptsRef.current - 1), 15000);
          const jitter = baseDelay * 0.2 * (Math.random() * 2 - 1);
          const delay = baseDelay + jitter;
          retryTimerRef.current = setTimeout(connect, delay);
        } else {
          callbacksRef.current.clearActiveScan();
          callbacksRef.current.setIsScanning(false);
          callbacksRef.current.setError('Connection lost after 5 retries');
        }
      });
    };

    connect();

    return () => {
      abortControllerRef.current?.abort();
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
    };
  }, []);

  const startScan = useCallback(async (config: ScanConfig) => {
    if (isScanning) {
      abortControllerRef.current?.abort();
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    const sessionToken = Date.now();
    currentSessionTokenRef.current = sessionToken;

    setEvents([]);
    setIsScanning(true);
    setError(null);
    setIsClean(false);
    setActiveStage('preflight');
    eventBufferRef.current = [];
    scanConfigRef.current = config;
    currentScanIdRef.current = null;
    accumulatedFinding.current = {
      endpoint: null,
      sensitiveFields: [],
      confidenceScore: null,
      patch: null,
      patchSource: null,
      regressionTest: null,
      prUrl: null,
      exploitConfirmedAt: null,
      verificationResult: null,
      curlReproduction: null,
      victimResourceId: null,
      method: null,
    };
    setEndpointProgress({
      current: null,
      method: null,
      status: null,
      completed: 0,
      total: 0,
      log: [],
    });

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      const response = await fetch(`/api/scan`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config),
        signal: abortController.signal,
      });

      if (sessionToken !== currentSessionTokenRef.current) return;
      if (!response.ok) throw new Error(`Failed to start scan: ${response.statusText}`);

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) throw new Error('Response body is not readable');

      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            if (sessionToken !== currentSessionTokenRef.current) return;
            const dataStr = line.replace('data: ', '').trim();
            if (dataStr) {
              try {
                const event = JSON.parse(dataStr) as SSEEvent;
                handleSSEEvent(event, sessionToken);
              } catch (e) {
                console.error('Failed to parse SSE event:', dataStr, e);
              }
            }
          }
        }
      }
      
      // Final flush
      if (flushTimeoutRef.current) clearTimeout(flushTimeoutRef.current);
      if (sessionToken === currentSessionTokenRef.current) flushBuffer();

    } catch (err: unknown) {
      if (sessionToken === currentSessionTokenRef.current && err instanceof Error && err.name !== 'AbortError') {
        setError(err.message || 'An unknown error occurred');
        setActiveStage('landing');
        clearActiveScan();
      }
    } finally {
      if (sessionToken === currentSessionTokenRef.current) {
        setIsScanning(false);
        abortControllerRef.current = null;
      }
    }
  }, [flushBuffer, handleSSEEvent, isScanning]);

  const stopScan = useCallback(() => {
    currentSessionTokenRef.current += 1;
    if (abortControllerRef.current) abortControllerRef.current.abort();
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
    setIsScanning(false);
    setActiveStage('landing');
    clearActiveScan();
  }, []);

  return { activeStage, setActiveStage, events, isScanning, error, isClean, startScan, stopScan, endpointProgress };
}
