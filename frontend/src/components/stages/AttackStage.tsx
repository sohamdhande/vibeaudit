import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { BOLAFinding, SSEEvent, SensitiveField } from '@/types';
import { TerminalWindow } from '../ui/TerminalWindow';
import { TerminalLineData } from '../ui/TerminalLine';
import { ExploitReveal } from './ExploitReveal';
import { ShieldAlert } from 'lucide-react';

interface EndpointProgressEntry {
  endpoint: string;
  method: string;
  status: 'testing' | 'vulnerable' | 'safe';
  timestamp: number;
}

interface EndpointProgress {
  current: string | null;
  method: string | null;
  status: 'testing' | 'vulnerable' | 'safe' | null;
  completed: number;
  total: number;
  log: EndpointProgressEntry[];
}

interface AttackStageProps {
  events: SSEEvent[];
  endpointProgress: EndpointProgress;
}

export function AttackStage({ events, endpointProgress }: AttackStageProps) {
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    document.body.classList.add('bg-attack-mode');
    return () => {
      document.body.classList.remove('bg-attack-mode');
    };
  }, []);

  // Auto-scroll the progress log
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [endpointProgress.log.length]);

  const attackEvents = events.filter((e) => e.stage === 'attack');
  
  // Filter out 'data' type events to avoid duplicating them in the terminal
  // since the ExploitReveal component will handle the dramatic display.
  // Also filter out testing/vulnerable/safe since they're shown in the progress panel.
  const terminalEvents = attackEvents.filter((e) => e.type !== 'data' && e.type !== 'testing' && e.type !== 'vulnerable' && e.type !== 'safe');
  
  const lines: TerminalLineData[] = terminalEvents.map((e, idx) => ({
    id: `attack-${idx}-${e.timestamp}`,
    content: e.message,
    timestamp: e.timestamp,
    type: e.type === 'finding' ? 'error' : 'log'
  }));

  const findingEvent = attackEvents.find(e => e.type === 'finding');
  let finding = findingEvent?.payload as BOLAFinding | undefined;

  if (finding) {
    const dataEvents = attackEvents.filter(e => e.type === 'data');
    const sensitiveFields = dataEvents.map(e => e.payload).filter(Boolean);
    
    const cvssLog = attackEvents.find(e => e.type === 'log' && e.message.includes('CVSS'));
    const cvssScore = cvssLog ? parseFloat(cvssLog.message.match(/CVSS\s+([\d.]+)/)?.[1] || '0') : finding.cvssScore || 0;
    
    const reproLog = attackEvents.find(e => e.type === 'log' && e.message.includes('Reproduction:'));
    const curlReproduction = reproLog ? reproLog.message.replace('Reproduction: ', '').trim() : finding.curlReproduction || '';

    finding = {
      ...finding,
      sensitiveFields: sensitiveFields as unknown as SensitiveField[],
      cvssScore,
      curlReproduction
    };
  }

  const pct = endpointProgress.total > 0
    ? Math.round((endpointProgress.completed / endpointProgress.total) * 100)
    : 0;

  const statusIcon = (status: 'testing' | 'vulnerable' | 'safe') => {
    switch (status) {
      case 'testing': return '🔍';
      case 'safe': return '✅';
      case 'vulnerable': return '🔴';
    }
  };

  const statusColor = (status: 'testing' | 'vulnerable' | 'safe') => {
    switch (status) {
      case 'testing': return 'text-white/50';
      case 'safe': return 'text-brand-green';
      case 'vulnerable': return 'text-brand-red';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0 }}
      className="flex flex-col h-screen p-6 max-w-7xl mx-auto gap-6"
    >
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h2 className="text-xl font-mono text-brand-red tracking-widest uppercase text-glow-red flex items-center gap-2">
            <ShieldAlert className="w-5 h-5" /> Phase 2: Exploit Engine
          </h2>
          <p className="text-white/50 text-sm font-mono mt-1">Executing dual-session BOLA heuristics on discovered endpoints...</p>
        </div>
      </div>

      {/* Endpoint Progress Panel */}
      {endpointProgress.total > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="shrink-0 bg-[#050505] border border-brand-red/20 rounded-md p-4 font-mono text-sm"
        >
          {/* Progress bar header */}
          <div className="flex items-center justify-between mb-2">
            <span className="text-white/70 text-xs tracking-widest uppercase">Endpoint Progress</span>
            <span className="text-brand-red text-xs font-bold">
              {endpointProgress.completed}/{endpointProgress.total} ({pct}%)
            </span>
          </div>

          {/* Progress bar */}
          <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden mb-3">
            <motion.div
              className="h-full rounded-full"
              style={{
                background: 'linear-gradient(90deg, #ef4444, #f97316)',
              }}
              initial={{ width: 0 }}
              animate={{ width: `${pct}%` }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
            />
          </div>

          {/* Currently testing */}
          {endpointProgress.current && endpointProgress.status === 'testing' && (
            <div className="flex items-center gap-2 mb-3 text-white/50 text-xs">
              <span className="animate-pulse">🔍</span>
              <span className="text-white/70 font-bold">{endpointProgress.method}</span>
              <span>{endpointProgress.current}</span>
            </div>
          )}

          {/* Scrolling log */}
          <div className="max-h-28 overflow-y-auto border-t border-white/5 pt-2 space-y-0.5">
            {endpointProgress.log
              .filter(entry => entry.status !== 'testing')
              .map((entry, idx) => (
              <div
                key={`ep-${idx}-${entry.timestamp}`}
                className={`flex items-center gap-2 text-xs ${statusColor(entry.status)}`}
              >
                <span className="w-4 text-center shrink-0">{statusIcon(entry.status)}</span>
                <span className="font-bold shrink-0 w-10">{entry.method}</span>
                <span className="truncate">{entry.endpoint}</span>
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </motion.div>
      )}
      
      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">
        <TerminalWindow 
          lines={lines} 
          className="flex-1 min-h-0 h-full"
          title="ATTACK_VECTOR_STREAM"
          accentColor="red"
        />

        <AnimatePresence>
          {finding && (
            <motion.div
              initial={{ opacity: 0, x: 20, width: 0 }}
              animate={{ opacity: 1, x: 0, width: '40%' }}
              className="h-full flex flex-col gap-4 overflow-hidden"
            >
              <ExploitReveal finding={finding} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
