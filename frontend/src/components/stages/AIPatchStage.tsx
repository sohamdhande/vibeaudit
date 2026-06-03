import React from 'react';
import { motion } from 'framer-motion';
import { PatchResult, SSEEvent } from '@/types';
import { TerminalWindow } from '../ui/TerminalWindow';
import { TerminalLineData } from '../ui/TerminalLine';
import { GlassCard } from '../ui/GlassCard';
import { Cpu } from 'lucide-react';
import { VibeAuditLogo } from '../VibeAuditLogo';
import { Highlight, themes } from 'prism-react-renderer';
import { cn } from '@/lib/utils';

interface AIPatchStageProps {
  events: SSEEvent[];
}

interface CodeViewerProps {
  code: string;
  language?: string;
  highlightLine?: number;
  highlightRegex?: RegExp;
  className?: string;
  variant?: 'red' | 'green' | 'blue';
}

export function CodeViewer({ 
  code, 
  language = 'typescript', 
  highlightLine,
  highlightRegex,
  className,
  variant = 'blue'
}: CodeViewerProps) {
  
  let highlightBg = 'bg-blue-500/20 border-l-2 border-blue-500';
  if (variant === 'red') highlightBg = 'bg-brand-red/20 border-l-2 border-brand-red';
  if (variant === 'green') highlightBg = 'bg-brand-green/20 border-l-2 border-brand-green';

  return (
    <Highlight theme={themes.vsDark} code={code || ''} language={language}>
      {({ className: prismClass, style, tokens, getLineProps, getTokenProps }) => (
        <pre 
          className={cn('text-sm font-mono overflow-auto p-4 rounded-md', prismClass, className)} 
          style={{ ...style, backgroundColor: 'transparent' }}
        >
          {tokens.map((line, i) => {
            const lineContent = line.map(token => token.content).join('');
            
            // Check if this line should be highlighted
            const isHighlightedByNumber = highlightLine === i + 1;
            const isHighlightedByRegex = highlightRegex && highlightRegex.test(lineContent);
            const isHighlighted = isHighlightedByNumber || isHighlightedByRegex;

            const { key: lineKey, ...lineProps } = getLineProps({ line, key: i }) as { key?: React.Key; [key: string]: unknown };
            return (
              <div 
                key={lineKey ?? i} 
                {...lineProps}
                className={cn(
                  'table-row',
                  isHighlighted ? highlightBg : 'border-l-2 border-transparent hover:bg-white/5'
                )}
              >
                <span className="table-cell select-none text-right pr-4 text-white/30 text-xs">
                  {i + 1}
                </span>
                <span className="table-cell pl-2">
                  {line.map((token, key) => {
                    const { key: tokenKey, ...tokenProps } = getTokenProps({ token, key }) as { key?: React.Key; [key: string]: unknown };
                    return <span key={tokenKey ?? key} {...tokenProps} />;
                  })}
                </span>
              </div>
            );
          })}
        </pre>
      )}
    </Highlight>
  );
}

const FALLBACK_VULNERABLE_CODE = `// Vulnerable route handler
// ⚠️ BOLA: No ownership check — any authenticated user can access any record
// The route fetches a resource by ID without verifying that the
// authenticated user is the owner of that resource.
//
// Waiting for source code from GitHub...`;

export function AIPatchStage({ events }: AIPatchStageProps) {
  const aiEvents = events.filter((e) => e.stage === 'ai');
  
  const patchEvent = aiEvents.find(e => e.type === 'patch');
  const patch = patchEvent?.payload as PatchResult | undefined;

  // We need to inject the patched code into the terminal stream gracefully
  const lines: TerminalLineData[] = aiEvents.map((e, idx) => {
    let content: string | React.ReactNode = e.message;

    // When the patch arrives, we render it beautifully inside the terminal
    if (e.type === 'patch' && patch) {
      content = (
        <div className="flex flex-col gap-2 mt-2 w-full max-w-full">
          <span className="text-brand-green font-bold">{e.message}</span>
          <div className="bg-black/80 rounded border border-brand-green/30 overflow-hidden w-full max-w-full">
            <div className="px-3 py-1 bg-brand-green/10 text-brand-green text-xs border-b border-brand-green/20 font-bold uppercase tracking-widest">
              Generated Fix ({patch?.filePath ?? 'app/api/records/[id]/route.ts'})
            </div>
            {/* The CodeViewer needs to be constrained so it doesn't break the flex layout */}
            <div className="max-w-full overflow-x-auto">
              <CodeViewer 
                code={patch?.patchedCode ?? ''} 
                variant="green" 
                highlightRegex={patch?.ownershipField ? new RegExp(patch.ownershipField) : undefined}
              />
            </div>
          </div>
        </div>
      );
    }

    return {
      id: `ai-${idx}-${e.timestamp}`,
      content,
      timestamp: e.timestamp,
      type: e.type === 'patch' ? 'success' : 'log'
    };
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.98 }}
      className="flex flex-col h-screen p-6 max-w-[1600px] mx-auto gap-6"
    >
      <div className="flex items-center gap-3 shrink-0">
        <Cpu className="w-6 h-6 text-blue-400" />
        <div>
          <h2 className="text-xl font-mono text-blue-400 tracking-widest uppercase text-glow-blue drop-shadow-[0_0_8px_rgba(96,165,250,0.8)]">
            Phase 3: AI Remediation
          </h2>
          <p className="text-white/50 text-sm font-mono mt-1">Generating and applying deterministic security patches...</p>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">
        {/* LEFT PANEL: Vulnerable Code Context */}
        <div className="flex-1 flex flex-col gap-2 min-w-0 h-full">
          <div className="flex items-center justify-between px-2 shrink-0">
            <span className="text-xs font-mono text-white/40 uppercase tracking-widest">
              Vulnerable Code ({patch?.filePath || 'app/api/records/[id]/route.ts'})
            </span>
            <div className="flex gap-2">
              <span className="text-xs font-mono text-brand-red bg-brand-red/10 px-2 py-0.5 rounded border border-brand-red/20 uppercase">
                Missing Ownership Check
              </span>
              {patch?.patchSource && (
                <span className={`text-xs font-mono px-2 py-0.5 rounded border uppercase ${
                  patch.patchSource === 'github_ai' 
                    ? 'text-brand-green bg-brand-green/10 border-brand-green/20'
                    : patch.patchSource === 'response_ai'
                    ? 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20'
                    : 'text-orange-400 bg-orange-400/10 border-orange-400/20'
                }`}>
                  {patch.patchSource === 'github_ai' ? 'Source-Aware' 
                   : patch.patchSource === 'response_ai' ? 'Response-Based' 
                   : 'Template'}
                </span>
              )}
            </div>
          </div>
          
          <GlassCard className="flex-1 overflow-hidden p-0 bg-[#0a0505] border-brand-red/30 flex flex-col" glowColor="none">
            {patch ? (
              <div className="flex-1 overflow-auto max-w-full custom-scrollbar">
                <CodeViewer 
                  code={patch?.originalCode || FALLBACK_VULNERABLE_CODE} 
                  variant="red"
                  highlightRegex={/findUnique/}
                />
              </div>
            ) : (
              <div className="p-6 font-mono text-sm text-white/30 animate-pulse flex flex-col items-center justify-center h-full gap-4">
                <VibeAuditLogo size="icon" animated={true} />
                <div className="w-8 h-8 border-4 border-white/10 border-t-white/40 rounded-full animate-spin" />
                Extracting vulnerability context from source control...
              </div>
            )}
          </GlassCard>
        </div>

        {/* RIGHT PANEL: Streaming AI Synthesis Terminal */}
        <div className="flex-1 flex flex-col min-w-0 h-full">
          <div className="text-xs font-mono text-white/40 px-2 uppercase tracking-widest mb-2 shrink-0">
            AI Synthesis Stream
          </div>
          <TerminalWindow 
            lines={lines} 
            className="flex-1 min-h-0"
            title="ai-patch-engine"
            accentColor="blue"
          />
        </div>
      </div>
    </motion.div>
  );
}
