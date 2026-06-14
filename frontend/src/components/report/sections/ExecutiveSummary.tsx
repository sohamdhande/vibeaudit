import React from 'react';
import type { ReportData } from '@/types';
import { getSeverityColor, getSeverityLabel, getCvssVector, getRegulatoryImpact } from '../utils/redact';

interface ExecutiveSummaryProps {
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

export function ExecutiveSummary({ data, pageNumber }: ExecutiveSummaryProps) {
  const { finding, patch } = data;
  const categories = [...new Set(finding.sensitiveFields.map(f => f.category))].join(', ');

  const severity = getSeverityLabel(finding.confidenceScore);
  const severityColor = getSeverityColor(severity);
  const cvssVector = getCvssVector(finding.cvssScore, finding.attackerAuthenticated);
  const regulations = getRegulatoryImpact(finding.sensitiveFields.map(f => f.category));

  return (
    <div className="report-page" style={{ background: '#ffffff', color: '#111111', position: 'relative' }}>
      <h2 className="report-section-heading">Executive Summary</h2>

      <p>
        A critical authorization vulnerability was identified in the target application.
        The {finding.method} endpoint at{' '}
        <code style={{ fontFamily: "'Courier New', monospace", background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px', wordBreak: 'break-all' }}>
          {finding.endpoint}
        </code>{' '}
        fails to validate resource ownership before returning data. This allows any authenticated
        user to access resources belonging to other users by simply substituting the
        resource identifier in the request URL.
      </p>

      {/* Risk Dashboard */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', margin: '20px 0' }}>
        <div style={{ border: `2px solid ${severityColor}`, borderRadius: '6px', padding: '12px', textAlign: 'center', background: `${severityColor}08` }}>
          <div style={{ fontSize: '10px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
            Severity
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, color: severityColor }}>
            {severity}
          </div>
        </div>
        <div style={{ border: '2px solid #e0e0e0', borderRadius: '6px', padding: '12px', textAlign: 'center' }}>
          <div style={{ fontSize: '10px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
            CVSS Score
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, color: severityColor }}>
            {finding.cvssScore}
          </div>
          <div style={{ fontSize: '9px', color: '#888', fontFamily: "'Courier New', monospace", marginTop: '4px' }}>
            {cvssVector}
          </div>
        </div>
        <div style={{ border: '2px solid #e0e0e0', borderRadius: '6px', padding: '12px', textAlign: 'center' }}>
          <div style={{ fontSize: '10px', color: '#666', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
            Confidence
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, color: '#111111' }}>
            {finding.confidenceScore >= 80 ? 'High' : finding.confidenceScore >= 50 ? 'Medium' : 'Low'}
          </div>
        </div>
      </div>

      {/* Regulatory Impact */}
      {regulations.length > 0 && (
        <div style={{
          fontSize: '12px',
          color: '#555555',
          marginBottom: '20px',
          padding: '10px 14px',
          background: '#fef9e7',
          border: '1px solid #f0e0a0',
          borderRadius: '4px',
        }}>
          <strong style={{ color: '#333333' }}>Regulatory Impact:</strong>{' '}
          {regulations.join(' · ')}
        </div>
      )}

      <h3 className="report-sub-heading">Business Impact</h3>
      <p>
        An authenticated attacker can access any user&apos;s{' '}
        <span style={{ wordBreak: 'break-all', fontFamily: "'Courier New', monospace", background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px', fontSize: '12px' }}>
          {finding.endpoint}
        </span>{' '}
        resource by substituting their own session token with a victim&apos;s resource ID.
        {categories && (
          <>
            {' '}Data exposed includes: <strong>{categories}</strong>.
            Potential regulatory impact depends on the exposed data type, which may
            include obligations under {regulations.join(', ') || 'applicable data privacy frameworks'}.
          </>
        )}
        {' '}This constitutes a direct violation of the principle of least privilege.
      </p>

      <h3 className="report-sub-heading">Recommendation</h3>
      <p>
        Implement server-side ownership validation on the{' '}
        <code style={{ fontFamily: "'Courier New', monospace", background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px' }}>
          {patch.ownershipField}
        </code>{' '}
        field in every route handler that returns user-scoped resources, and deploy
        the auto-generated patch immediately.
      </p>

      <div style={PAGE_NUMBER_STYLE}>Page {pageNumber} of 9 — CONFIDENTIAL</div>
    </div>
  );
}
