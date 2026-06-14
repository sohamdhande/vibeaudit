import React from 'react';
import { ScanMeta } from '@/types';
import { GlassCard } from '../ui/GlassCard';

interface ScanScoreboardProps {
  meta: ScanMeta;
}

function StatRow({ label, value, subValue }: { label: string, value: string | number | boolean | null, subValue?: string }) {
  if (value === null || value === undefined) return null;
  return (
    <div className="flex justify-between py-1 border-b border-white/5 last:border-0 items-center">
      <span className="text-white/60 text-xs font-mono">{label}</span>
      <div className="text-right flex items-center gap-2">
        <span className="text-white/90 font-mono text-sm">{typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}</span>
        {subValue && <span className="text-white/40 text-xs font-mono">({subValue})</span>}
      </div>
    </div>
  );
}

function formatRate(num: number, den: number): string | undefined {
  if (den > 0 && num <= den && num >= 0) {
    return `${((num / den) * 100).toFixed(1)}%`;
  }
  return undefined;
}

export function ScanScoreboard({ meta }: ScanScoreboardProps) {
  const d = meta.discoveryStats;
  const r = meta.replayStats;
  const s = meta.skipReasons;
  const c = meta.confirmationStats;
  const rej = meta.rejectionReasons;
  const rem = meta.remediationStats;
  const gh = meta.githubStats;

  return (
    <div className="w-full grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-8">
      {/* DISCOVERY */}
      {d && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">Discovery</h3>
          <div className="flex flex-col">
            <StatRow label="Pages Visited" value={d.pagesVisited} />
            <StatRow label="Total Endpoints" value={d.totalEndpoints} />
            <StatRow label="Unique Endpoints" value={d.uniqueEndpoints} />
            <StatRow label="Parameterized" value={d.parameterizedEndpoints} subValue={formatRate(d.parameterizedEndpoints ?? 0, d.uniqueEndpoints ?? 0)} />
            <StatRow label="BOLA Candidates" value={d.bolaCandidates} subValue={formatRate(d.bolaCandidates ?? 0, d.uniqueEndpoints ?? 0)} />
          </div>
        </GlassCard>
      )}

      {/* REPLAY */}
      {r && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">Replay</h3>
          <div className="flex flex-col">
            <StatRow label="Eligible" value={r.eligible} />
            <StatRow label="Tested" value={r.tested} subValue={formatRate(r.tested ?? 0, r.eligible ?? 0)} />
            <StatRow label="Skipped" value={r.skipped} subValue={formatRate(r.skipped ?? 0, r.eligible ?? 0)} />
          </div>
        </GlassCard>
      )}

      {/* SKIP REASONS */}
      {s && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">Skip Reasons</h3>
          <div className="flex flex-col">
            <StatRow label="Missing Object ID" value={s.missingObjectId} />
            <StatRow label="Auth Replay Failed" value={s.authReplayFailed} />
            <StatRow label="No Second User" value={s.noSecondUser} />
            <StatRow label="Unsupported Route" value={s.unsupportedRoute} />
            <StatRow label="Parse Failure" value={s.parseFailure} />
            <StatRow label="Other" value={s.other} />
          </div>
        </GlassCard>
      )}

      {/* CONFIRMATION */}
      {c && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">Confirmation</h3>
          <div className="flex flex-col">
            <StatRow label="Candidates" value={c.candidates} />
            <StatRow label="Confirmed" value={c.confirmed} subValue={formatRate(c.confirmed ?? 0, r?.tested ?? 0)} />
            <StatRow label="Rejected" value={c.rejected} subValue={formatRate(c.rejected ?? 0, r?.tested ?? 0)} />
          </div>
        </GlassCard>
      )}

      {/* REJECTION REASONS */}
      {rej && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">Rejection Reasons</h3>
          <div className="flex flex-col">
            <StatRow label="Returned 403" value={rej.returned403} />
            <StatRow label="Returned 404" value={rej.returned404} />
            <StatRow label="Response Mismatch" value={rej.responseMismatch} />
            <StatRow label="Low Diff Similarity" value={rej.diffSimilarityTooLow} />
            <StatRow label="Insufficient Evidence" value={rej.insufficientEvidence} />
            <StatRow label="Other" value={rej.other} />
          </div>
        </GlassCard>
      )}

      {/* REMEDIATION */}
      {rem && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">Remediation</h3>
          <div className="flex flex-col">
            <StatRow label="Attempted" value={rem.attempted} />
            <StatRow label="Generated" value={rem.generated} />
            <StatRow label="Skipped" value={rem.skipped} />
            <StatRow label="Validated" value={rem.validated} />
            <StatRow label="Context Conf." value={rem.codeContextConfidence || '—'} />
            <StatRow label="Skip Reason" value={rem.patchSkippedReason || '—'} />
          </div>
        </GlassCard>
      )}

      {/* GITHUB */}
      {gh && (
        <GlassCard className="p-4 bg-white/[0.02]">
          <h3 className="text-brand-green text-xs font-mono tracking-widest uppercase mb-3">GitHub Integration</h3>
          <div className="flex flex-col">
            <StatRow label="Repo Configured" value={gh.repoProvided} />
            <StatRow label="Token Provided" value={gh.tokenProvided} />
            <StatRow label="PR Attempted" value={gh.attempted} />
            <StatRow label="PR Created" value={gh.created} />
            {gh.prUrl ? (
              <div className="flex justify-between py-1 border-b border-white/5 last:border-0 items-center">
                <span className="text-white/60 text-xs font-mono">PR Link</span>
                <a href={gh.prUrl} target="_blank" rel="noreferrer" className="text-brand-green hover:underline font-mono text-sm">View PR ↗</a>
              </div>
            ) : (
              <StatRow label="Skip Reason" value={gh.prSkippedReason || '—'} />
            )}
          </div>
        </GlassCard>
      )}

    </div>
  );
}
