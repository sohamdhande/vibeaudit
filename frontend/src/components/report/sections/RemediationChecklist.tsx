import React from 'react';
import type { ReportData } from '@/types';

interface RemediationChecklistProps {
  data: ReportData;
  pageNumber: number;
}

const PAGE_NUMBER_STYLE: React.CSSProperties = {
  position: 'absolute',
  bottom: '12mm',
  right: '16mm',
  fontSize: '9px',
  color: '#666666',
  fontFamily: 'monospace',
};

function extractPattern(endpoint: string): string {
  if (!endpoint) return '/:id';
  let pattern = endpoint.replace(/[0-9a-f]{8,}[0-9a-z]*/gi, ':id');
  pattern = pattern.replace(/\/\d+/g, '/:id');
  pattern = pattern.replace(/\/[a-z]{1,4}[0-9][a-z0-9]{8,}/gi, '/:id');
  return pattern;
}

export function RemediationChecklist({ data, pageNumber }: RemediationChecklistProps) {
  const { patch, finding, scanMeta } = data;
  const endpointPattern = extractPattern(finding.endpoint);

  const items = [
    `Apply patch to ${patch.filePath}`,
    'Run regression test — confirm 403 response',
    `Audit all endpoints matching ${endpointPattern} pattern`,
    'Add ownership validation to shared auth middleware',
    'Peer code review sign-off obtained',
    'Deployed to staging environment',
    'VibeAudit re-scan on staging — result: Clean',
    'Deployed to production',
    scanMeta.prUrl ? `GitHub PR merged: ${scanMeta.prUrl}` : 'GitHub PR merged',
    'Security ticket closed',
  ];

  return (
    <div className="report-page" style={{ background: '#ffffff', color: '#111111', position: 'relative' }}>
      <h2 className="report-section-heading">Remediation Checklist</h2>

      <p>
        Use this checklist to track the remediation process. Each item should
        be completed and verified before the vulnerability can be considered resolved.
      </p>

      <ul className="report-checklist">
        {items.map((item, i) => (
          <li key={i}>
            <span className="report-checkbox">□</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>

      <div style={{
        marginTop: '24px',
        padding: '16px',
        background: '#fffbeb',
        border: '1px solid #fcd34d',
        borderRadius: '6px',
        fontSize: '12px',
        color: '#92400e',
        lineHeight: 1.6,
      }}>
        <strong>Note:</strong> This checklist is provided as a guide. Your
        organization&apos;s security policies may require additional steps
        including but not limited to: security architecture review, penetration
        testing by a third party, and formal risk acceptance sign-off.
      </div>

      <div style={PAGE_NUMBER_STYLE}>Page {pageNumber} of 9 — CONFIDENTIAL</div>
    </div>
  );
}
