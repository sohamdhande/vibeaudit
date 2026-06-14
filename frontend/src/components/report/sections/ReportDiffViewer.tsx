import React from 'react';
import type { ReportData } from '@/types';
export interface DiffLine {
  type: 'hunk' | 'added' | 'removed' | 'context';
  content: string;
  lineNumber: number | null;
}

/**
 * Parses a unified diff string into structured DiffLine objects.
 * Handles: hunk headers, added/removed/context lines, file headers (skipped).
 * Does not crash on malformed input — renders as context lines.
 */
export function parseDiff(unifiedDiff: string): DiffLine[] {
  if (!unifiedDiff || unifiedDiff.trim().length === 0) {
    return [{ type: 'context', content: 'Diff not available — see GitHub PR', lineNumber: null }];
  }

  // Check if it's a real diff (contains @@ headers)
  const isRealDiff = unifiedDiff.includes('@@');
  
  if (!isRealDiff) {
    // Case B: No hunk headers, treat as a single added block
    return unifiedDiff.split('\n').map((line, idx) => ({
      type: 'added',
      content: line.startsWith('+') ? line.substring(1) : line,
      lineNumber: idx + 1,
    }));
  }

  // Case A: Real diff
  const rawLines = unifiedDiff.split('\n');
  const result: DiffLine[] = [];
  let currentLineNumber = 1;

  for (const raw of rawLines) {
    // Skip file headers (--- and +++ lines)
    if (raw.startsWith('---') || raw.startsWith('+++')) {
      continue;
    }

    // Hunk header: @@ -N,N +N,N @@
    if (raw.startsWith('@@')) {
      const match = raw.match(/@@ -\d+(?:,\d+)? \+(\d+)/);
      if (match) {
        currentLineNumber = parseInt(match[1], 10);
      }
      result.push({ type: 'hunk', content: raw, lineNumber: null });
      continue;
    }

    // Added line
    if (raw.startsWith('+')) {
      result.push({
        type: 'added',
        content: raw.substring(1),
        lineNumber: currentLineNumber,
      });
      currentLineNumber++;
      continue;
    }

    // Removed line
    if (raw.startsWith('-')) {
      result.push({
        type: 'removed',
        content: raw.substring(1),
        lineNumber: null,
      });
      continue;
    }

    // Context line (starts with space or is plain text)
    const content = raw.startsWith(' ') ? raw.substring(1) : raw;
    if (raw.length === 0 && result.length > 0) {
      // Empty line at end of diff — skip
      continue;
    }
    result.push({
      type: 'context',
      content,
      lineNumber: currentLineNumber,
    });
    currentLineNumber++;
  }

  return result;
}

interface ReportDiffViewerProps {
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

export function ReportDiffViewer({ data, pageNumber }: ReportDiffViewerProps) {
  const { patch, scanMeta } = data;
  const displayPatch = patch.displayPatch;

  if (!displayPatch || displayPatch.trim() === '' || scanMeta.patchGenerationAttempted === false) {
    return (
      <div className="report-page" style={{ position: 'relative', background: '#ffffff', color: '#111111' }}>
        <h2 className="report-section-heading" style={{ color: '#c0392b', borderBottomColor: '#c0392b' }}>
          Patch Generation Skipped
        </h2>
        <div style={{ padding: '16px', background: '#fef2f2', border: '1px solid #fca5a5', borderRadius: '6px', color: '#991b1b', fontSize: '13px', lineHeight: 1.6 }}>
          <strong style={{ display: 'block', marginBottom: '8px' }}>Reason: Insufficient code context for safe remediation</strong>
          {scanMeta.patchGenerationSkippedReason || 'The analysis engine could not confidently identify the framework, file path, ownership field, or auth context.'}
        </div>
        
        <div style={{ marginTop: '24px', fontSize: '13px', color: '#333' }}>
          <h3 className="report-sub-heading">Detected Context</h3>
          <ul style={{ paddingLeft: '20px', lineHeight: 1.8 }}>
            <li><strong>Endpoint:</strong> <code style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px', fontFamily: "'Courier New', monospace" }}>{data.finding.endpoint}</code></li>
            {patch.ownershipField && patch.ownershipField !== 'manual-review' && (
              <li><strong>Ownership Field:</strong> <code style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px', fontFamily: "'Courier New', monospace" }}>{patch.ownershipField}</code></li>
            )}
            {patch.authLibrary && (
              <li><strong>Auth Library:</strong> {patch.authLibrary}</li>
            )}
            {patch.filePath && patch.filePath !== 'unknown' && (
              <li><strong>File Path:</strong> {patch.filePath}</li>
            )}
          </ul>
        </div>
        <div style={PAGE_NUMBER_STYLE}>Page {pageNumber} of 9 — CONFIDENTIAL</div>
      </div>
    );
  }

  const lines = parseDiff(displayPatch);

  return (
    <div className="report-page" style={{ background: '#ffffff', color: '#111111', position: 'relative' }}>
      <h2 className="report-section-heading">AI-Generated Security Patch</h2>

      <div className="report-diff-container">
        <div className="report-diff-header">
          📄 {patch.filePath}
        </div>

        {lines.map((line, idx) => {
          let lineClass = 'report-diff-context';
          let gutter = ' ';

          if (line.type === 'hunk') {
            lineClass = 'report-diff-hunk';
            gutter = '';
          } else if (line.type === 'added') {
            lineClass = 'report-diff-added';
            gutter = '+';
          } else if (line.type === 'removed') {
            lineClass = 'report-diff-removed';
            gutter = '−';
          }

          return (
            <div key={idx} className={`report-diff-line ${lineClass}`}>
              <span className="report-diff-line-number">
                {line.lineNumber !== null ? line.lineNumber : ''}
              </span>
              <span className="report-diff-gutter">{gutter}</span>
              <span className="report-diff-code">
                {line.type === 'hunk' ? line.content : (line.content || '\u00A0')}
              </span>
            </div>
          );
        })}
      </div>

      {/* Patch explanation */}
      <div style={{ marginTop: '24px' }}>
        {patch.reasoning && patch.reasoning.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <h3 className="report-sub-heading">Patch Explanation</h3>
            <ul style={{ paddingLeft: '20px', fontSize: '13px', lineHeight: 1.8, color: '#333333' }}>
              {patch.reasoning.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          </div>
        )}

        <div style={{ fontSize: '13px', color: '#555555', marginTop: '12px' }}>
          {patch.ownershipField && (
            <div>
              <strong style={{ color: '#333333' }}>Ownership field used:</strong>{' '}
              <code className="report-mono" style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px' }}>
                {patch.ownershipField}
              </code>
            </div>
          )}
          {patch.authLibrary && (
            <div style={{ marginTop: '4px' }}>
              <strong style={{ color: '#333333' }}>Auth library:</strong>{' '}
              <code className="report-mono" style={{ background: '#f3f4f6', padding: '1px 4px', borderRadius: '3px' }}>
                {patch.authLibrary}
              </code>
            </div>
          )}
        </div>
      </div>

      <div style={PAGE_NUMBER_STYLE}>Page {pageNumber} of 9 — CONFIDENTIAL</div>
    </div>
  );
}
