import React, { useCallback, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import type { ReportData } from '@/types';
import { CoverPage } from './sections/CoverPage';
import { ExecutiveSummary } from './sections/ExecutiveSummary';
import { VulnerabilityDetails } from './sections/VulnerabilityDetails';
import { EvidenceComparison } from './sections/EvidenceComparison';
import { TechnicalFinding } from './sections/TechnicalFinding';
import { ReportDiffViewer } from './sections/ReportDiffViewer';
import { RegressionTest } from './sections/RegressionTest';
import { RemediationChecklist } from './sections/RemediationChecklist';
import { ScanMetadata } from './sections/ScanMetadata';
import './report.css';

interface ReportGeneratorProps {
  data: ReportData | null;
  visible?: boolean;
}

export function ReportGenerator({ data, visible = true }: ReportGeneratorProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const generateReport = useCallback(() => {
    window.print();
  }, []);

  if (!data) return null;

  // The portal mounts directly to document.body so the CSS
  // `body > *:not(#vibeaudit-report-root)` selector works correctly.
  const reportPortal = (
    <div id="vibeaudit-report-root">
      <div id="vibeaudit-report">
        <CoverPage data={data} />
        <ExecutiveSummary data={data} pageNumber={2} />
        <VulnerabilityDetails data={data} pageNumber={3} />
        <EvidenceComparison data={data} pageNumber={4} />
        <TechnicalFinding data={data} pageNumber={5} />
        <ReportDiffViewer data={data} pageNumber={6} />
        <RegressionTest regressionTest={data.regressionTest} pageNumber={7} />
        <RemediationChecklist data={data} pageNumber={8} />
        <ScanMetadata data={data} pageNumber={9} />
      </div>
    </div>
  );

  return (
    <>
      {visible && (
        <>
          <button
            onClick={generateReport}
            id="vibeaudit-download-report"
            className="inline-flex items-center gap-2 text-xs font-mono bg-white/10 text-white/80 hover:bg-white/20 hover:text-white px-4 py-2.5 rounded border border-white/10 hover:border-white/20 transition-all"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7,10 12,15 17,10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Download PDF Report
          </button>

          <div style={{ marginTop: '6px' }}>
            <span className="text-[10px] font-mono text-white/30 ml-2">
              Use &quot;Save as PDF&quot; in the print dialog
            </span>
            <p style={{ fontSize: '11px', color: '#888', marginTop: '4px', marginLeft: '8px' }}>
              In the print dialog: uncheck "Headers and footers" for a clean report
            </p>
          </div>
        </>
      )}

      {mounted && createPortal(reportPortal, document.body)}
    </>
  );
}
