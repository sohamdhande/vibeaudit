import React, { useEffect, useState, useMemo } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';
import { SSEEvent, BOLAFinding, PatchResult, ScanSummary } from '@/types';
import type { ReportData, ScanMeta } from '@/types';
import { CheckCircle, ExternalLink, GitPullRequest } from 'lucide-react';
import { VibeAuditLogo } from '../VibeAuditLogo';
import { GlassCard } from '../ui/GlassCard';
import { TerminalWindow } from '../ui/TerminalWindow';
import { TerminalLineData } from '../ui/TerminalLine';
import { ReportGenerator } from '../report/ReportGenerator';
import { ScanScoreboard } from './ScanScoreboard';

interface VictoryStageProps { events: SSEEvent[]; isClean?: boolean; summary?: ScanSummary | null; }

type RevealState = 'VERIFYING' | 'RESOLVED' | 'CARDS_REVEAL' | 'BANNER_REVEAL';

export function VictoryStage({ events, isClean, summary }: VictoryStageProps) {
  const [state, setState] = useState<RevealState>('VERIFYING');
  const [mountTime] = useState<number>(() => Date.now());

  const verifyEvents = events.filter((e) => e.stage === 'verify');
  const doneEvent = events.find(e => (e.stage === 'done' && e.type === 'complete') || (e.stage === 'complete' && e.type === 'clean'));

  // Build ReportData from accumulated SSE events
  const reportData: ReportData | null = useMemo(() => {
    if (!summary || !summary.results.finding) return null;

    return {
      scanConfig: { targetUrl: summary.meta.targetUrl, userA: { email: '', password: '' }, userB: { email: '', password: '' } },
      finding: summary.results.finding as BOLAFinding,
      patch: summary.results.patch as PatchResult,
      regressionTest: summary.results.regressionTest || '// No regression test generated',
      scanMeta: {
        scanId: summary.meta.scanId,
        startTime: summary.meta.startTime,
        endTime: summary.meta.endTime,
        endpointsDiscovered: summary.telemetry.discovery.totalEndpoints,
        endpointsTested: summary.telemetry.replay.tested,
        scannerVersion: summary.meta.scannerVersion,
        aiModel: 'AI-powered analysis',
        prUrl: summary.results.prUrl,
        prGenerationAttempted: summary.telemetry.github.attempted,
        prGenerationSkippedReason: summary.telemetry.github.prSkippedReason,
        githubRepoOwner: null,
        githubRepoName: null,
        patchValidated: summary.telemetry.remediation.validated,
        patchGenerationAttempted: summary.telemetry.remediation.attempted,
        patchGenerationSkippedReason: summary.telemetry.remediation.patchSkippedReason,
        testedEndpoints: undefined,
        discoveryStats: summary.telemetry.discovery as any,
        replayStats: summary.telemetry.replay as any,
        skipReasons: summary.telemetry.replay.skipReasons as any,
        confirmationStats: summary.telemetry.confirmation as any,
        rejectionReasons: summary.telemetry.confirmation.rejectionReasons as any,
        remediationStats: summary.telemetry.remediation as any,
        githubStats: summary.telemetry.github as any,
      }
    };
  }, [summary]);

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

  const handleExportBenchmark = () => {
    if (!summary) return;
    
    const d = summary.telemetry.discovery;
    const r = summary.telemetry.replay;
    const c = summary.telemetry.confirmation;
    const rem = summary.telemetry.remediation;
    const gh = summary.telemetry.github;

    const row = {
      scan_id: summary.meta.scanId || '',
      target_url: summary.meta.targetUrl || '',
      duration_seconds: summary.meta.durationMs ? (summary.meta.durationMs / 1000).toFixed(2) : '',
      pages_visited: d.pagesVisited ?? '',
      total_endpoints: d.totalEndpoints ?? '',
      unique_endpoints: d.uniqueEndpoints ?? '',
      parameterized_endpoints: d.parameterizedEndpoints ?? '',
      bola_candidates: d.bolaCandidates ?? '',
      replay_eligible: r.eligible ?? '',
      replay_tested: r.tested ?? '',
      replay_skipped: r.skipped ?? '',
      confirmed_findings: c.confirmed ?? '',
      rejected_candidates: c.rejected ?? '',
      patch_generation_attempted: rem.attempted ?? '',
      patch_generated: rem.generated ?? '',
      patch_skipped: rem.skipped ?? '',
      patch_validation_failed: rem.validationFailed ?? '',
      pr_generation_attempted: gh.attempted ?? '',
      pr_created: gh.created ?? '',
      pr_skipped: gh.skipped ?? '',
      findings_count: summary.results.finding ? 1 : 0,
      artifact_folder_path: `/artifacts/${summary.meta.scanId}/`
    };

    const headers = Object.keys(row).join(',');
    const values = Object.values(row).map(v => {
      if (v === null || v === undefined || v === '') return '';
      if (typeof v === 'string') return `"${v.replace(/"/g, '""')}"`;
      return v;
    }).join(',');
    const csvContent = `${headers}\n${values}`;
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `benchmark_row_${summary.meta.scanId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

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

      {events.find(e => e.stage === 'done' && e.type === 'error') ? (
        <div className="w-full mb-12">
          <TerminalWindow 
            lines={[...lines, { id: 'error', content: events.find(e => e.stage === 'done' && e.type === 'error')!.message, timestamp: Date.now(), type: 'error' }]}
            className="h-[250px]"
            title="SYSTEM_ERROR"
            accentColor="red"
          />
          <div className="flex justify-center mt-8">
            <button onClick={() => window.location.reload()} className="px-6 py-2 bg-red-500/20 text-red-500 border border-red-500/50 rounded font-mono hover:bg-red-500/30 transition-colors">
              Restart Scanner
            </button>
          </div>
        </div>
      ) : (
        <div className="w-full mb-12">
          <TerminalWindow 
            lines={lines} 
            className="h-[250px]"
            title="VERIFICATION_SYSTEM"
            accentColor="green"
          />
        </div>
      )}

      {!events.find(e => e.stage === 'done' && e.type === 'error') && (
        <AnimatePresence>
        {(state === 'CARDS_REVEAL' || state === 'BANNER_REVEAL') && (
          <motion.div 
            variants={containerVariants}
            initial="hidden"
            animate="show"
            className="w-full flex flex-col gap-6"
          >
                <ScanScoreboard meta={{
                  ...summary?.meta,
                  discoveryStats: summary?.telemetry?.discovery,
                  replayStats: summary?.telemetry?.replay,
                  skipReasons: summary?.telemetry?.replay?.skipReasons,
                  confirmationStats: summary?.telemetry?.confirmation,
                  rejectionReasons: summary?.telemetry?.confirmation?.rejectionReasons,
                  remediationStats: summary?.telemetry?.remediation,
                  githubStats: summary?.telemetry?.github,
                } as any} />



            <AnimatePresence>
              {state === 'BANNER_REVEAL' && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mt-16 flex flex-col items-center gap-6"
                >
                  {/* Scan Artifacts Section */}
                  {summary && reportData && (
                    <div className="w-full max-w-3xl flex flex-col gap-4 mt-8 mb-8 p-6 bg-black/40 border border-white/10 rounded-lg">
                      <h3 className="text-lg font-mono text-white/90 border-b border-white/10 pb-2">Scan Artifacts Evidence</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm font-mono text-white/70">
                        <div><span className="text-white/40">Scan ID:</span> {reportData.scanMeta.scanId}</div>
                        <div><span className="text-white/40">Duration:</span> {summary.meta.durationMs ? (summary.meta.durationMs / 1000).toFixed(1) + 's' : 'N/A'}</div>
                        <div><span className="text-white/40">Endpoints Discovered:</span> {summary.telemetry.discovery.totalEndpoints}</div>
                        <div><span className="text-white/40">Findings:</span> {summary.results.finding ? 1 : 0}</div>
                        <div className="col-span-1 md:col-span-2 break-all"><span className="text-white/40">Artifact Folder Path:</span> /artifacts/{reportData.scanMeta.scanId}/</div>
                      </div>
                      
                      <div className="flex flex-wrap gap-4 mt-4">
                        <a 
                          href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000'}/artifacts/${reportData.scanMeta.scanId}/report.json`}
                          target="_blank"
                          rel="noreferrer"
                          className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded font-mono text-xs text-white transition-colors"
                        >
                          Download report.json
                        </a>
                        <a 
                          href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000'}/artifacts/${reportData.scanMeta.scanId}/findings.json`}
                          target="_blank"
                          rel="noreferrer"
                          className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded font-mono text-xs text-white transition-colors"
                        >
                          Download findings.json
                        </a>
                        <a 
                          href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000'}/artifacts/${reportData.scanMeta.scanId}/zip`}
                          className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded font-mono text-xs text-white transition-colors"
                        >
                          Download all artifacts as ZIP
                        </a>
                        <button 
                          onClick={handleExportBenchmark}
                          className="px-4 py-2 bg-brand-green/10 hover:bg-brand-green/20 border border-brand-green/30 rounded font-mono text-xs text-brand-green transition-colors flex items-center gap-2"
                        >
                          Export benchmark row
                        </button>
                      </div>
                    </div>
                  )}

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
      )}
    </motion.div>
  );
}
