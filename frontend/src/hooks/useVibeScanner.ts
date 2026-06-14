import { useState, useCallback, useRef, useEffect } from 'react';
import { ScanConfig, ScanHistoryEntry, SSEEvent, SSEStage, getSeverity, ScanSummary } from '../types';



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
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
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

    // Handle summary event
    if ((event.stage as string) === 'summary' && (event.type as string) === 'result') {
      const summary = event.summary || event.payload?.summary;
      if (summary) {
        setScanSummary(summary);
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
    setScanSummary(null);
    setIsScanning(true);
    setError(null);
    setIsClean(false);
    setActiveStage('preflight');
    eventBufferRef.current = [];
    scanConfigRef.current = config;
    currentScanIdRef.current = null;
    
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
      if (!response.ok) {
        let errMsg = response.statusText;
        try {
          const body = await response.json();
          if (body && body.error) errMsg = body.error;
        } catch { }
        throw new Error(`Failed to start scan: ${errMsg}`);
      }

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

  return { activeStage, setActiveStage, events, isScanning, error, isClean, startScan, stopScan, endpointProgress, scanSummary };
}
