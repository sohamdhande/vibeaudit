import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Trash2, Clock, ShieldAlert, ExternalLink, FileDown } from 'lucide-react';
import { ScanHistoryEntry } from '@/types';
import type { ReportData } from '@/types';
import { ReportGenerator } from '../report/ReportGenerator';

interface ScanHistoryModalProps {
  entry: ScanHistoryEntry;
  onClose: () => void;
  onDelete: (id: string) => void;
}

const PRINT_STYLES = `
@media print {
  .diff-line-add {
    background-color: #dcfce7 !important;
    color: #166534 !important;
    border-left-color: #22c55e !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  .diff-line-remove {
    background-color: #fef2f2 !important;
    color: #991b1b !important;
    border-left-color: #ef4444 !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  .diff-line-chunk {
    color: #6b7280 !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  .diff-container {
    border: 1px solid #d1d5db !important;
    background: #fff !important;
  }
}
`;

export function DiffViewer({ patch }: { patch: string }) {
  let lines = patch.split('\n');

  // If no diff formatting is found, treat everything as an addition
  if (!lines.some(line => line.startsWith('+') || line.startsWith('-'))) {
    lines = lines.map(line => `+${line}`);
  }

  return (
    <>
      <style>{PRINT_STYLES}</style>
      <div className="diff-container font-mono text-xs rounded-md border border-white/10 overflow-x-auto bg-black/50">
        {lines.map((line, idx) => {
          let bg = '';
          let textColor = 'text-white/70';
          let borderColor = 'border-transparent';
          let printClass = '';

          if (line.startsWith('+')) {
            bg = 'bg-green-500/10';
            textColor = 'text-green-400';
            borderColor = 'border-green-500';
            printClass = 'diff-line-add';
          } else if (line.startsWith('-')) {
            bg = 'bg-red-500/10';
            textColor = 'text-red-400';
            borderColor = 'border-red-500';
            printClass = 'diff-line-remove';
          } else if (line.startsWith('@@')) {
            textColor = 'text-blue-400/60';
            printClass = 'diff-line-chunk';
          }

          return (
            <div
              key={idx}
              className={`px-3 py-0.5 border-l-2 ${borderColor} ${bg} ${textColor} ${printClass} whitespace-pre`}
            >
              {line || '\u00A0'}
            </div>
          );
        })}
      </div>
    </>
  );
}

export function ScanHistoryModal({ entry, onClose, onDelete }: ScanHistoryModalProps) {
  const [reportUnavailable, setReportUnavailable] = useState(false);
  const [currentReportData, setCurrentReportData] = useState<ReportData | null>(null);

  if (!entry) return null;

  const handleDownloadReport = () => {
    const stored = localStorage.getItem(`vibeaudit_report_${entry.id}`);
    
    if (!stored) {
      setReportUnavailable(true);
      return;
    }

    try {
      const reportData = JSON.parse(stored);
      setCurrentReportData(reportData);
      setTimeout(() => window.print(), 100);
    } catch {
      setReportUnavailable(true);
    }
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          className="relative w-full max-w-3xl max-h-[85vh] overflow-y-auto bg-black border border-white/10 rounded-xl shadow-2xl p-6"
        >
          <div className="flex justify-between items-start mb-6">
            <div>
              <h3 className="text-lg font-mono font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-red-500" />
                Scan Result
              </h3>
              <p className="text-sm font-mono text-white/50 mt-1">{entry.id}</p>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-md hover:bg-white/10 text-white/50 hover:text-white transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="space-y-4">
            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-mono text-white/50">Status</span>
                <span className={`text-sm font-mono font-bold px-2 py-1 rounded ${
                  entry.status === 'vulnerable' ? 'bg-red-500/20 text-red-400' :
                  entry.status === 'clean' ? 'bg-green-500/20 text-green-400' :
                  'bg-white/10 text-white/70'
                }`}>
                  {entry.status ? entry.status.toUpperCase() : 'UNKNOWN'}
                </span>
              </div>
            </div>

            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-mono text-white/50">Time</span>
                <span className="text-sm font-mono text-white flex items-center gap-1.5">
                  <Clock className="w-4 h-4" />
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          {entry.endpoint && (
            <div className="mt-4 p-4 bg-white/5 border border-white/10 rounded-lg">
              <h4 className="text-sm font-mono text-white/70 mb-2">Vulnerable Endpoint</h4>
              <p className="text-xs font-mono text-red-400 break-all">{entry.endpoint}</p>
            </div>
          )}

          {entry.sensitiveFields && entry.sensitiveFields.length > 0 && (
            <div className="mt-4 p-4 bg-white/5 border border-white/10 rounded-lg">
              <h4 className="text-sm font-mono text-white/70 mb-2">Exposed Fields</h4>
              <div className="flex flex-wrap gap-2">
                {entry.sensitiveFields.map((f, i) => (
                  <span key={i} className="text-xs font-mono bg-red-500/20 text-red-400 px-2 py-1 rounded border border-red-500/30">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}

          {entry.patch && (
            <div className="mt-4">
              <h4 className="text-sm font-mono text-white/70 mb-2">Generated Patch</h4>
              <div className="max-h-64 overflow-y-auto rounded-lg border border-white/10">
                <DiffViewer patch={entry.patch} />
              </div>
            </div>
          )}

          {entry.prUrl && (
            <div className="mt-4 p-4 bg-brand-green/10 border border-brand-green/20 rounded-lg flex items-center justify-between">
              <span className="text-sm font-mono text-brand-green">Pull Request Opened!</span>
              <a href={entry.prUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-xs font-mono text-brand-green hover:underline">
                View PR <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}

          <div className="mt-8 flex flex-col pt-4 border-t border-white/10">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <button
                  onClick={handleDownloadReport}
                  disabled={entry.status === 'clean'}
                  title={entry.status === 'clean' ? 'No vulnerability found — no report available' : 'Download PDF report'}
                  className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-md border transition-colors ${
                    entry.status === 'clean'
                      ? 'bg-white/5 text-white/30 border-white/5 cursor-not-allowed'
                      : 'bg-white/10 text-white/80 border-white/10 hover:bg-white/20 hover:text-white hover:border-white/20 cursor-pointer'
                  }`}
                >
                  <FileDown className="w-4 h-4" />
                  Download PDF Report
                </button>
                <span style={{ fontSize: '12px', color: '#888' }}>
                  In print dialog: uncheck &quot;Headers and footers&quot;
                </span>
              </div>
              <button
                onClick={() => onDelete(entry.id)}
                className="flex items-center gap-2 px-3 py-1.5 text-sm font-mono text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-md transition-colors"
              >
                <Trash2 className="w-4 h-4" /> Delete
              </button>
            </div>
            
            {reportUnavailable && (
              <p style={{ fontSize: '12px', color: '#c0392b', margin: '0' }}>
                Report data not available — only scans from this browser session have full PDF reports.
              </p>
            )}

            {currentReportData && (
              <ReportGenerator
                data={currentReportData}
                visible={false}
              />
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}