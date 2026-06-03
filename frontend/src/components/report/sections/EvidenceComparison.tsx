import React from 'react';
import type { ReportData } from '@/types';
import { getSeverityColor, getSeverityLabel } from '../utils/redact';

interface EvidenceComparisonProps {
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

function summarizeData(data: Record<string, unknown>): { key: string; value: string }[] {
  if (!data || typeof data !== 'object') return [];
  return Object.entries(data).slice(0, 8).map(([key, value]) => {
    let display: string;
    if (value === null || value === undefined) {
      display = 'null';
    } else if (typeof value === 'string') {
      display = value.length > 40 ? value.substring(0, 37) + '...' : value;
    } else if (typeof value === 'object') {
      display = Array.isArray(value) ? `[Array(${value.length})]` : `{Object}`;
    } else {
      display = String(value);
    }
    return { key, value: display };
  });
}

export function EvidenceComparison({ data, pageNumber }: EvidenceComparisonProps) {
  const { finding } = data;
  const severity = getSeverityLabel(finding.confidenceScore);
  const severityColor = getSeverityColor(severity);

  const stolenFields = summarizeData(finding.stolenData);
  const sensitiveKeys = new Set(finding.sensitiveFields.map(f => f.key));

  return (
    <div className="report-page" style={{ background: '#ffffff', color: '#111111', position: 'relative' }}>
      <h2 className="report-section-heading" style={{ borderBottomColor: severityColor }}>Evidence</h2>

      <div style={{
        background: '#fef2f2',
        border: `1px solid ${severityColor}`,
        borderRadius: '6px',
        padding: '12px 16px',
        marginBottom: '24px',
        fontSize: '13px',
        fontWeight: 600,
        color: severityColor,
        textAlign: 'center',
      }}>
        Cross-User Data Access Confirmed
      </div>

      {/* Two-column comparison */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
        {/* Victim Column */}
        <div>
          <div style={{
            background: '#22863a',
            color: '#ffffff',
            padding: '8px 12px',
            borderRadius: '6px 6px 0 0',
            fontSize: '11px',
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase' as const,
          }}>
            Victim Response (User A)
          </div>
          <div style={{ border: '1px solid #d1d5db', borderTop: 'none', borderRadius: '0 0 6px 6px', overflow: 'hidden' }}>
            <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse' }}>
              <tbody>
                <tr style={{ background: '#f9fafb' }}>
                  <td style={{ padding: '6px 10px', fontWeight: 600, color: '#555', width: '35%' }}>Status</td>
                  <td style={{ padding: '6px 10px', fontFamily: "'Courier New', monospace", color: '#22863a' }}>200 OK</td>
                </tr>
                <tr>
                  <td style={{ padding: '6px 10px', fontWeight: 600, color: '#555' }}>Auth</td>
                  <td style={{ padding: '6px 10px', fontSize: '10px' }}>Authenticated (owner)</td>
                </tr>
                {stolenFields.map((field, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? '#f9fafb' : '#ffffff' }}>
                    <td style={{ padding: '6px 10px', fontWeight: 600, color: '#555', fontFamily: "'Courier New', monospace", fontSize: '10px' }}>{field.key}</td>
                    <td style={{
                      padding: '6px 10px',
                      fontFamily: "'Courier New', monospace",
                      fontSize: '10px',
                      color: sensitiveKeys.has(field.key) ? '#c0392b' : '#333',
                    }}>
                      {sensitiveKeys.has(field.key) ? '[SENSITIVE]' : field.value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Attacker Column */}
        <div>
          <div style={{
            background: severityColor,
            color: '#ffffff',
            padding: '8px 12px',
            borderRadius: '6px 6px 0 0',
            fontSize: '11px',
            fontWeight: 600,
            letterSpacing: '0.05em',
            textTransform: 'uppercase' as const,
          }}>
            Attacker Response (User B)
          </div>
          <div style={{ border: '1px solid #d1d5db', borderTop: 'none', borderRadius: '0 0 6px 6px', overflow: 'hidden' }}>
            <table style={{ width: '100%', fontSize: '11px', borderCollapse: 'collapse' }}>
              <tbody>
                <tr style={{ background: '#fef2f2' }}>
                  <td style={{ padding: '6px 10px', fontWeight: 600, color: '#555', width: '35%' }}>Status</td>
                  <td style={{ padding: '6px 10px', fontFamily: "'Courier New', monospace", color: severityColor, fontWeight: 600 }}>200 OK ⚠</td>
                </tr>
                <tr>
                  <td style={{ padding: '6px 10px', fontWeight: 600, color: '#555' }}>Auth</td>
                  <td style={{ padding: '6px 10px', fontSize: '10px' }}>
                    {finding.attackerAuthenticated ? 'Authenticated (non-owner)' : 'Unauthenticated'}
                  </td>
                </tr>
                {stolenFields.map((field, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? '#fef2f2' : '#ffffff' }}>
                    <td style={{ padding: '6px 10px', fontWeight: 600, color: '#555', fontFamily: "'Courier New', monospace", fontSize: '10px' }}>{field.key}</td>
                    <td style={{
                      padding: '6px 10px',
                      fontFamily: "'Courier New', monospace",
                      fontSize: '10px',
                      color: sensitiveKeys.has(field.key) ? '#c0392b' : '#333',
                      fontWeight: sensitiveKeys.has(field.key) ? 600 : 400,
                    }}>
                      {sensitiveKeys.has(field.key) ? '⚠ LEAKED' : field.value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <p style={{ fontSize: '12px', color: '#666', fontStyle: 'italic' }}>
        The attacker (User B) received an identical HTTP 200 response containing User A&apos;s data.
        Fields marked as SENSITIVE or LEAKED indicate data that should have been restricted
        by server-side authorization checks. This confirms a Broken Object Level Authorization
        (BOLA) vulnerability allowing cross-user data access.
      </p>

      <div style={PAGE_NUMBER_STYLE}>Page {pageNumber} of 9 — CONFIDENTIAL</div>
    </div>
  );
}
