import React from 'react';
import { motion } from 'framer-motion';
import { CheckCircle2, Circle } from 'lucide-react';
import { SSEEvent } from '@/types';
import { GlassCard } from '../ui/GlassCard';
import { VibeAuditLogo } from '../VibeAuditLogo';

interface PreflightStageProps {
  events: SSEEvent[];
}

export function PreflightStage({ events }: PreflightStageProps) {
  const preflightEvents = events.filter((e) => e.stage === 'preflight');

  // Static list of checks we expect
  const checks = [
    { id: 'init', label: 'Scanner initialized', keyword: 'initialized' },
    { id: 'target', label: 'Target locked', keyword: 'Target:' },
    { id: 'github', label: 'GitHub integration', keyword: 'GitHub' },
    { id: 'ai', label: 'AI engine connected', keyword: 'AI engine' },
    { id: 'branch', label: 'Base branch identified', keyword: 'Base branch' },
  ];

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="flex flex-col items-center justify-center min-h-screen p-6"
    >
      <div className="mb-8 text-center">
        <div className="flex justify-center mb-4">
          <VibeAuditLogo size="icon" animated={true} />
        </div>
        <h2 className="text-3xl font-mono tracking-widest text-white/90">PREFLIGHT SEQUENCE</h2>
        <div className="h-1 w-24 bg-brand-green mx-auto mt-4 glow-green rounded-full" />
      </div>

      <GlassCard className="w-full max-w-lg" glowColor="none">
        <div className="space-y-4 font-mono text-sm">
          {checks.map((check, index) => {
            // Find if there's an event matching this check
            const matchedEvent = preflightEvents.find((e) => e.message.includes(check.keyword));
            const isComplete = !!matchedEvent;
            const isWarning = matchedEvent?.message.includes('⚠');

            return (
              <motion.div
                key={check.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.15 }}
                className="flex items-center gap-4"
              >
                {isComplete ? (
                  isWarning ? (
                    <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }}>
                      <CheckCircle2 className="w-5 h-5 text-yellow-500" />
                    </motion.div>
                  ) : (
                    <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }}>
                      <CheckCircle2 className="w-5 h-5 text-brand-green drop-shadow-[0_0_8px_rgba(0,255,65,0.8)]" />
                    </motion.div>
                  )
                ) : (
                  <Circle className="w-5 h-5 text-white/20 animate-pulse" />
                )}
                
                <span className={isComplete ? (isWarning ? 'text-yellow-500/80' : 'text-white/90') : 'text-white/40'}>
                  {matchedEvent ? matchedEvent.message.replace('✓ ', '').replace('⚠ ', '') : `Waiting for ${check.label}...`}
                </span>
              </motion.div>
            );
          })}
        </div>
      </GlassCard>
    </motion.div>
  );
}
