import React, { useEffect, useState, useMemo } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';
import { SSEEvent, BOLAFinding, PatchResult } from '@/types';
import type { ReportData, ScanMeta } from '@/types';
import { CheckCircle, ExternalLink, GitPullRequest } from 'lucide-react';
import { VibeAuditLogo } from '../VibeAuditLogo';
import { GlassCard } from '../ui/GlassCard';
import { TerminalWindow } from '../ui/TerminalWindow';
import { TerminalLineData } from '../ui/TerminalLine';
import { ReportGenerator } from '../report/ReportGenerator';

interface VictoryStageProps {
  events: SSEEvent[];
  isClean?: boolean;
}

type RevealState = 'VERIFYING' | 'RESOLVED' | 'CARDS_REVEAL' | 'BANNER_REVEAL';

export function VictoryStage({ events, isClean }: VictoryStageProps) {
  const [state, setState] = useState<RevealState>('VERIFYING');
  const [mountTime] = useState<number>(() => Date.now());

  const verifyEvents = events.filter((e) => e.stage === 'verify');
  const doneEvent = events.find(e => (e.stage === 'done' && e.type === 'complete') || (e.stage === 'complete' && e.type === 'clean'));
  const cleanEvent = events.find(e => e.stage === 'complete' && e.type === 'clean');
  
  const githubEvent = events.find(e => e.stage === 'github' && e.type === 'complete');
  const summaryEvent = events.find(e => e.stage === 'summary' && e.type === 'result');
  
  const prUrl = githubEvent?.payload?.prUrl;

  // Build ReportData from accumulated SSE events
  const reportData: ReportData | null = useMemo(() => {
    if (isClean) return null;

    // Extract finding from attack events
    const findingEvent = events.find(e => e.stage === 'attack' && e.type === 'finding');
    const patchEvent = events.find(e => e.stage === 'ai' && e.type === 'patch');
    const testEvent = events.find(e => (e.stage === 'ai' || e.stage === 'github') && (e.payload?.regressionTest || e.payload?.testCode));

    if (!findingEvent?.payload) return null;

    const fp = findingEvent.payload;
    const finding: BOLAFinding = {
      endpoint: (fp.endpoint || fp.url || '') as string,
      method: (fp.method as string) || 'GET',
      victimToken: '[REDACTED]',
      attackerToken: '[REDACTED]',
      victimResourceId: (fp.victimResourceId as string) || '',
      stolenData: (fp.stolenData as Record<string, unknown>) || {},
      sensitiveFields: Array.isArray(fp.sensitiveFields)
        ? fp.sensitiveFields.map((f: unknown) =>
            typeof f === 'object' && f !== null && 'key' in f
              ? (f as { key: string; value: unknown; category: 'PII' | 'PHI' | 'FINANCIAL' | 'AUTH' | 'UNKNOWN' })
              : { key: String(f), value: '[REDACTED]', category: 'UNKNOWN' as const }
          )
        : [],
      attackerAuthenticated: (fp.attackerAuthenticated as boolean) ?? true,
      curlReproduction: (fp.curlReproduction as string) || '',
      cvssScore: (fp.cvssScore as number) || 8.5,
      confidenceScore: (fp.confidenceScore as number) || 0,
    };

    const pp = patchEvent?.payload || {};
    const patch: PatchResult = {
      originalCode: '',
      patchedCode: (pp.patchedCode as string) || '',
      displayPatch: (pp.displayPatch as string) || (pp.patchedCode as string) || (pp.patch as string) || '',
      filePath: (pp.filePath as string) || 'unknown',
      ownershipField: (pp.ownershipField as string) || 'userId',
      authLibrary: (pp.authLibrary as string) || 'unknown',
      sessionAccessor: (pp.sessionAccessor as string) || 'req.user.id',
      reasoning: Array.isArray(pp.reasoning) ? pp.reasoning as string[] : [],
      patchSource: (pp.patchSource as 'github_ai' | 'response_ai' | 'deterministic') || 'response_ai',
    };

    const regressionTest = (testEvent?.payload?.regressionTest as string) || (testEvent?.payload?.testCode as string) || '// No regression test generated';

    const scanMeta: ScanMeta = {
      scanId: (events[0]?.payload?.scanId as string) || `scan_${mountTime}`,
      startTime: events[0]?.timestamp || mountTime,
      endTime: summaryEvent?.timestamp || mountTime,
      endpointsDiscovered: summaryEvent?.endpointsFound || 0,
      endpointsTested: summaryEvent?.attacksAttempted || 0,
      scannerVersion: '1.0.0',
      aiModel: 'AI-powered analysis',
      prUrl: (prUrl as string) || null,
    };

    return {
      scanConfig: { targetUrl: summaryEvent?.targetUrl || 'Unknown', userA: { email: '', password: '' }, userB: { email: '', password: '' } },
      finding,
      patch,
      regressionTest,
      scanMeta,
    };
  }, [events, isClean, prUrl, summaryEvent, mountTime]);

  const lines: TerminalLineData[] = verifyEvents.map((e, idx) => ({
    id: `verify-${idx}-${e.timestamp}`,
    content: e.message,
    timestamp: e.timestamp,
    type: e.type === 'complete' ? 'success' : 'log'
  }));

  const sequenceStarted = React.useRef(false);

  useEffect(() => {
    if (doneEvent && !sequenceStarted.current) {
      sequenceStarted.current = true;
      setState('RESOLVED');
      
      // Delay before showing cards
      setTimeout(() => {
        setState('CARDS_REVEAL');
        
        // Delay before showing final banner
        setTimeout(() => {
          setState('BANNER_REVEAL');
        }, 1500); // 1.5s after cards start revealing
      }, 800);
    }
  }, [doneEvent]);

  // Framer motion variants for stagger
  const containerVariants: Variants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.3 }
    }
  };

  const itemVariants: Variants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: "easeOut" as const } }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      className="flex flex-col items-center min-h-screen p-6 max-w-5xl mx-auto"
    >
      {/* Logo branding */}
      <div className="flex justify-center mt-8" style={{ marginBottom: '24px' }}>
        <VibeAuditLogo size="md" animated={false} />
      </div>

      <div className="w-full mb-12">
        <TerminalWindow 
          lines={lines} 
          className="h-[250px]"
          title="VERIFICATION_SYSTEM"
          accentColor="green"
        />
      </div>

      <AnimatePresence>
        {(state === 'CARDS_REVEAL' || state === 'BANNER_REVEAL') && (
          <motion.div 
            variants={containerVariants}
            initial="hidden"
            animate="show"
            className="w-full flex flex-col gap-6"
          >
            {/* Conditional Cards / Banner based on vulnerabilities */}
            {!isClean ? (
              <>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full">
                  {/* Card 1 */}
                  <motion.div variants={itemVariants}>
                    <GlassCard glowColor="green" className="h-full bg-brand-green/5 border-brand-green/20">
                      <div className="flex flex-col h-full justify-between gap-4">
                        <div className="flex items-center gap-3 text-brand-green">
                          <CheckCircle className="w-6 h-6 shrink-0" />
                          <span className="font-mono text-sm tracking-widest uppercase">Patch Committed</span>
                        </div>
                        {prUrl && (
                          <a 
                            href={prUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-xs font-mono bg-brand-green/10 text-brand-green hover:bg-brand-green/20 px-3 py-2 rounded border border-brand-green/30 transition-colors w-fit"
                          >
                            <GitPullRequest className="w-3 h-3" />
                            View Pull Request <ExternalLink className="w-3 h-3 ml-1" />
                          </a>
                        )}
                      </div>
                    </GlassCard>
                  </motion.div>

                  {/* Card 2 */}
                  <motion.div variants={itemVariants}>
                    <GlassCard glowColor="green" className="h-full bg-brand-green/5 border-brand-green/20">
                      <div className="flex items-center gap-3 text-brand-green">
                        <CheckCircle className="w-6 h-6 shrink-0" />
                        <span className="font-mono text-sm tracking-widest uppercase">Regression Test Committed</span>
                      </div>
                    </GlassCard>
                  </motion.div>

                  {/* Card 3 */}
                  <motion.div variants={itemVariants}>
                    <GlassCard glowColor="green" className="h-full bg-brand-green/5 border-brand-green/20">
                      <div className="flex items-center gap-3 text-brand-green">
                        <CheckCircle className="w-6 h-6 shrink-0" />
                        <span className="font-mono text-sm tracking-widest uppercase">GitHub Actions Armed</span>
                      </div>
                    </GlassCard>
                  </motion.div>
                </div>

                <AnimatePresence>
                  {state === 'BANNER_REVEAL' && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.95, filter: 'blur(10px)' }}
                      animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
                      transition={{ duration: 1, ease: "easeOut" }}
                      className="mt-8 text-center"
                    >
                      <div className="inline-flex items-center justify-center mb-6">
                        <VibeAuditLogo size="md" animated={false} />
                      </div>
                      <h1 className="text-3xl md:text-4xl font-bold tracking-tight text-white">
                        Your application is protected today
                        <br />
                        <span className="text-brand-green text-glow-green">and on every future deployment.</span>
                      </h1>
                      {summaryEvent?.targetUrl && (
                        <p className="mt-4 text-white/50 font-mono text-sm">{summaryEvent.targetUrl}</p>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </>
            ) : (
              <AnimatePresence>
                {state === 'BANNER_REVEAL' && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95, filter: 'blur(10px)' }}
                    animate={{ opacity: 1, scale: 1, filter: 'blur(0px)' }}
                    transition={{ duration: 1, ease: "easeOut" }}
                    className="mt-8 text-center"
                  >
                    <div className="inline-flex items-center justify-center mb-6">
                      <VibeAuditLogo size="md" animated={false} />
                    </div>
                    <h1 className="text-3xl md:text-4xl font-bold tracking-tight text-white">
                      No vulnerabilities found
                      <br />
                      <span className="text-brand-green text-glow-green">— your app looks protected.</span>
                    </h1>
                    {Boolean(cleanEvent?.payload?.reason) && (
                      <p className="mt-4 text-white/50 font-mono text-sm uppercase tracking-widest">
                        Status: {(cleanEvent!.payload!.reason as string).replace('_', ' ')}
                      </p>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            )}

            {/* Summary Stats */}
            {summaryEvent && (
              <motion.div variants={itemVariants} className="flex justify-center gap-8 mt-4">
                <div className="text-center font-mono">
                  <div className="text-2xl font-bold text-white/90">{summaryEvent.endpointsFound ?? 0}</div>
                  <div className="text-xs text-white/50 uppercase tracking-widest">Endpoints Found</div>
                </div>
                <div className="text-center font-mono">
                  <div className="text-2xl font-bold text-white/90">{summaryEvent.attacksAttempted ?? 0}</div>
                  <div className="text-xs text-white/50 uppercase tracking-widest">Attacks Attempted</div>
                </div>
                <div className="text-center font-mono">
                  <div className="text-2xl font-bold text-brand-green text-glow-green">{summaryEvent.vulnerabilities ?? 0}</div>
                  <div className="text-xs text-brand-green/70 uppercase tracking-widest">Vulnerabilities Found</div>
                </div>
              </motion.div>
            )}

            <AnimatePresence>
              {state === 'BANNER_REVEAL' && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-16 flex flex-col items-center gap-6"
                >
                  {/* PDF Report Download */}
                  {reportData && (
                    <div className="flex items-center">
                      <ReportGenerator data={reportData} />
                    </div>
                  )}

                  <button 
                    onClick={() => window.location.reload()}
                    className="text-white/40 hover:text-white/80 text-xs font-mono transition-colors uppercase tracking-widest"
                  >
                    ← Terminate Session
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
