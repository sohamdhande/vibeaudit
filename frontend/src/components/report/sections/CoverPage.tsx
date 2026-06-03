import React from 'react';
import type { ReportData } from '@/types';
import { formatReportDate, getSeverityColor, getSeverityLabel } from '../utils/redact';

interface CoverPageProps {
  data: ReportData;
}

export function CoverPage({ data }: CoverPageProps) {
  const severity = getSeverityLabel(data.finding.confidenceScore);
  const severityColor = getSeverityColor(severity);

  return (
    <div
      className="report-page report-cover"
      style={{ background: '#ffffff', color: '#111111', textAlign: 'center' }}
    >
      {/* Wordmark */}
      <div style={{ marginBottom: '32px', marginTop: '40px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px' }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#c0392b" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M12 8v4M12 16h.01" />
          </svg>
          <span style={{ fontSize: '36px', fontWeight: 600, letterSpacing: '-0.02em', color: '#111111' }}>
            Vibe<span style={{ color: '#c0392b' }}>Audit</span>
          </span>
        </div>
      </div>

      {/* Title */}
      <div style={{ maxWidth: '480px', margin: '0 auto' }}>
        <h1 style={{ fontSize: '28px', fontWeight: 500, color: '#111111', lineHeight: 1.3, marginBottom: '8px' }}>
          BOLA/IDOR Vulnerability Assessment Report
        </h1>

        <p style={{ fontSize: '14px', color: '#666666', marginBottom: '24px', fontStyle: 'italic' }}>
          Confidential Security Assessment
        </p>

        {/* Severity Badge */}
        <div style={{
          display: 'inline-block',
          background: severityColor,
          color: '#ffffff',
          padding: '10px 32px',
          borderRadius: '6px',
          fontSize: '18px',
          fontWeight: 700,
          letterSpacing: '0.15em',
          textTransform: 'uppercase' as const,
          marginBottom: '8px',
        }}>
          {severity}
        </div>

        <div style={{
          display: 'block',
          fontSize: '11px',
          color: '#666666',
          marginBottom: '28px',
          letterSpacing: '0.05em',
        }}>
          Overall Risk Rating
        </div>

        <hr style={{ border: 'none', borderTop: '2px solid #e0e0e0', margin: '0 0 24px 0' }} />

        {/* Metadata Table */}
        <table style={{
          width: '100%',
          fontSize: '13px',
          color: '#555555',
          borderCollapse: 'collapse',
          textAlign: 'left' as const,
        }}>
          <tbody>
            <tr style={{ borderBottom: '1px solid #f0f0f0' }}>
              <td style={{ padding: '8px 12px', fontWeight: 600, color: '#333333', width: '140px' }}>Target</td>
              <td style={{ padding: '8px 12px', fontFamily: "'Courier New', monospace", wordBreak: 'break-all' as const }}>{data.scanConfig.targetUrl}</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #f0f0f0', background: '#fafafa' }}>
              <td style={{ padding: '8px 12px', fontWeight: 600, color: '#333333' }}>Report ID</td>
              <td style={{ padding: '8px 12px', fontFamily: "'Courier New', monospace" }}>{data.scanMeta.scanId}</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #f0f0f0' }}>
              <td style={{ padding: '8px 12px', fontWeight: 600, color: '#333333' }}>Date</td>
              <td style={{ padding: '8px 12px' }}>{formatReportDate(data.scanMeta.endTime)}</td>
            </tr>
            <tr style={{ background: '#fafafa' }}>
              <td style={{ padding: '8px 12px', fontWeight: 600, color: '#333333' }}>Scanner Version</td>
              <td style={{ padding: '8px 12px' }}>VibeAudit {data.scanMeta.scannerVersion}</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Disclaimer */}
      <div style={{ marginTop: '48px', fontSize: '11px', color: '#888888', maxWidth: '400px', margin: '48px auto 0', lineHeight: 1.6, fontStyle: 'italic' }}>
        This report contains sensitive security information.
        Distribution is restricted to authorized personnel only.
      </div>
    </div>
  );
}
