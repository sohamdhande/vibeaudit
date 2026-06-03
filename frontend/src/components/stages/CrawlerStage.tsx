import React from 'react';
import { motion } from 'framer-motion';
import { SSEEvent } from '@/types';
import { TerminalWindow } from '../ui/TerminalWindow';
import { TerminalLineData } from '../ui/TerminalLine';

interface CrawlerStageProps {
  events: SSEEvent[];
}

export function CrawlerStage({ events }: CrawlerStageProps) {
  const crawlerEvents = events.filter((e) => e.stage === 'crawler');
  
  let authType: 'cookie' | 'jwt' | 'unknown' = 'unknown';
  const hasJwtLog = crawlerEvents.some(e => e.message.toLowerCase().includes('auth type detected: jwt') || e.message.toLowerCase().includes('bearer token mode'));
  const hasCookieLog = crawlerEvents.some(e => e.message.toLowerCase().includes('auth type detected: cookie'));
  
  if (hasJwtLog) authType = 'jwt';
  else if (hasCookieLog) authType = 'cookie';

  const lines: TerminalLineData[] = crawlerEvents.map((e, idx) => ({
    id: `crawler-${idx}-${e.timestamp}`,
    content: e.message,
    timestamp: e.timestamp,
    type: e.type === 'endpoint' ? 'success' : e.type === 'complete' ? 'success' : 'log'
  }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="flex flex-col h-screen p-6 max-w-6xl mx-auto"
    >
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-mono text-brand-green tracking-widest uppercase">Phase 1: Discovery</h2>
          <p className="text-white/50 text-sm font-mono mt-1">Authenticating and crawling target for exposed API routes...</p>
        </div>
        <div className="flex items-center gap-2">
           {authType === 'jwt' && (
              <span className="text-xs font-mono text-purple-400 bg-purple-400/10 px-3 py-1 rounded-full border border-purple-400/30 shadow-[0_0_10px_rgba(168,85,247,0.2)] flex items-center gap-1.5 uppercase tracking-widest">
                <span>🔑</span> JWT Auth
              </span>
           )}
           {authType === 'cookie' && (
              <span className="text-xs font-mono text-blue-400 bg-blue-400/10 px-3 py-1 rounded-full border border-blue-400/30 shadow-[0_0_10px_rgba(96,165,250,0.2)] flex items-center gap-1.5 uppercase tracking-widest">
                <span>🍪</span> Cookie Auth
              </span>
           )}
           {authType === 'unknown' && (
              <span className="text-xs font-mono text-white/40 bg-white/5 px-3 py-1 rounded-full border border-white/10 flex items-center gap-1.5 uppercase tracking-widest">
                <span>❓</span> Auth Unknown
              </span>
           )}
        </div>
      </div>
      
      <TerminalWindow 
        lines={lines} 
        className="flex-1 min-h-0"
        title="PUPPETEER_CRAWLER_V2"
      />
    </motion.div>
  );
}
