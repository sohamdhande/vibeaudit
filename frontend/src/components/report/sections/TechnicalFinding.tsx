import React from 'react';
import type { ReportData } from '@/types';

interface TechnicalFindingProps {
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

export function TechnicalFinding({ data, pageNumber }: TechnicalFindingProps) {
  const { finding, patch } = data;
  const resourceId = finding.victimResourceId || finding.endpoint?.split('/').pop() || 'unknown';

  return (
    <div className="report-page" style={{ background: '#ffffff', color: '#111111', position: 'relative' }}>
      <h2 className="report-section-heading">Technical Finding</h2>

      <h3 className="report-sub-heading">Attack Methodology</h3>
      <ol style={{ paddingLeft: '20px', fontSize: '13px', lineHeight: 1.8, color: '#333333', marginBottom: '24px' }}>
        <li>Authenticated as User A (victim), captured session token</li>
        <li>
          Identified parameterized endpoint:{' '}
          <code className="report-mono" style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px', wordBreak: 'break-all' }}>
            {finding.endpoint}
          </code>
        </li>
        <li>
          Extracted resource ID:{' '}
          <code className="report-mono" style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px' }}>
            {resourceId}
          </code>
        </li>
        <li>Authenticated as User B (attacker), replayed request with User A&apos;s resource ID</li>
        <li>Server returned User A&apos;s data without performing any ownership check</li>
      </ol>

      <h3 className="report-sub-heading">Confirmation Method</h3>
      <p>
        The scanner confirmed this is a genuine BOLA vulnerability and not a false
        positive by verifying that the HTTP response body returned by the server
        contained data belonging to the victim user (resource ID{' '}
        <code className="report-mono" style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px' }}>
          {resourceId}
        </code>
        ), the response status code was 200 OK, and the response data fields matched
        the expected victim resource structure. The confidence score of{' '}
        <strong>{finding.confidenceScore}%</strong> reflects the degree of data
        overlap between the victim&apos;s expected response and the attacker&apos;s
        received response.
      </p>

      <h3 className="report-sub-heading">Ownership Field Missing</h3>
      <p>
        The field{' '}
        <code className="report-mono" style={{ background: '#fef2f2', color: '#c0392b', padding: '2px 6px', borderRadius: '3px', fontWeight: 600 }}>
          {patch.ownershipField}
        </code>{' '}
        was never compared against the authenticated user&apos;s identity in the
        route handler. This means any authenticated user can request any resource
        by ID, regardless of whether they own it. The authorization library in use
        ({patch.authLibrary}) provides session identity data, but the route handler
        does not leverage it for ownership validation.
      </p>

      <div style={PAGE_NUMBER_STYLE}>Page {pageNumber} of 9 — CONFIDENTIAL</div>
    </div>
  );
}
