import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, ChevronUp, Terminal, User, UserX, Clock, Trash2, ChevronRight } from 'lucide-react';
import { GlassCard } from '../ui/GlassCard';
import { ScanConfig, ScanHistoryEntry } from '@/types';
import { ScanHistoryModal } from '../ui/ScanHistoryModal';
import { VibeAuditLogo } from '../VibeAuditLogo';

function timeAgo(ts: number): string {
  const seconds = Math.floor((Date.now() - ts) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function getDateGroup(ts: number): string {
  const now = new Date();
  const d = new Date(ts);
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 86400000);
  if (d >= today) return 'Today';
  if (d >= yesterday) return 'Yesterday';
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${months[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
}



function getSeverityBadge(entry: ScanHistoryEntry): { emoji: string; label: string; cls: string } {
  if (entry.status === 'clean') return { emoji: '✅', label: 'CLEAN', cls: 'bg-green-500/20 text-green-400 border-green-500/30' };
  if (entry.status === 'vulnerable') return { emoji: '🔴', label: 'VULNERABLE', cls: 'bg-red-500/20 text-red-400 border-red-500/30' };
  if (entry.status === 'blocked') return { emoji: '✅', label: 'PATCHED', cls: 'bg-green-500/20 text-green-400 border-green-500/30' };
  return { emoji: '⚠️', label: 'ERROR', cls: 'bg-white/10 text-white/50 border-white/20' };
}

interface LandingStageProps {
  onStart: (config: ScanConfig) => void;
  error?: string | null;
}

export function LandingStage({ onStart, error }: LandingStageProps) {
  const [localError, setLocalError] = useState<string | null>(error || null);

  useEffect(() => {
    if (error) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setLocalError(error);
    }
  }, [error]);
  const [url, setUrl] = useState('');
  const [userAEmail, setUserAEmail] = useState('');
  const [userAPassword, setUserAPassword] = useState('');
  const [userBEmail, setUserBEmail] = useState('');
  const [userBPassword, setUserBPassword] = useState('');
  const [consent, setConsent] = useState(false);
  
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loginPath, setLoginPath] = useState('/login');
  const [pagesToCrawl, setPagesToCrawl] = useState('/dashboard');
  const [authType, setAuthType] = useState<'auto' | 'cookie' | 'jwt'>('auto');
  
  const [emailSelector, setEmailSelector] = useState('');
  const [passwordSelector, setPasswordSelector] = useState('');
  const [submitSelector, setSubmitSelector] = useState('');

  const [githubRepoOwner, setGithubRepoOwner] = useState('');
  const [githubRepoName, setGithubRepoName] = useState('');
  const [githubBaseBranch, setGithubBaseBranch] = useState('main');

  const loadShopVulnDemo = () => {
    setUrl('https://shopvuln.vercel.app');
    setUserAEmail('victim@shopvuln.com');
    setUserAPassword('password123');
    setUserBEmail('attacker@shopvuln.com');
    setUserBPassword('password123');
    setLoginPath('/login');
    setPagesToCrawl('/dashboard');
    setAuthType('auto');
    setGithubRepoOwner('sohamd1567');
    setGithubRepoName('shopvuln');
    setGithubBaseBranch('main');
    setShowAdvanced(true);
  };

  const [isScanning, setIsScanning] = useState(false);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<ScanHistoryEntry | null>(null);

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('vibeaudit_history') || '[]');
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setHistory(stored);
    } catch {}
  }, []);

  // Validation
  const isUrlValid = url.length === 0 || url.startsWith('http://') || url.startsWith('https://');
  const isUserAEmailValid = userAEmail.length === 0 || userAEmail.includes('@');
  const isUserBEmailValid = userBEmail.length === 0 || userBEmail.includes('@');
  
  const isReady = consent && 
                  url.length > 0 && isUrlValid &&
                  userAEmail.length > 0 && isUserAEmailValid && userAPassword.length > 0 &&
                  userBEmail.length > 0 && isUserBEmailValid && userBPassword.length > 0 &&
                  !isScanning;

  const handleSubmit = () => {
    if (!isReady) return;
    setIsScanning(true);
    
    const parsedPages = pagesToCrawl
      .split(/[\n,\s]+/)
      .map(p => p.trim())
      .filter(p => p.startsWith('/'));
      
    const selectors = {
      ...(emailSelector ? { email: emailSelector } : {}),
      ...(passwordSelector ? { password: passwordSelector } : {}),
      ...(submitSelector ? { submit: submitSelector } : {}),
    };

    const config: ScanConfig = {
      targetUrl: url,
      userA: { email: userAEmail, password: userAPassword },
      userB: { email: userBEmail, password: userBPassword },
      loginPath: loginPath || '/login',
      pagesToCrawl: parsedPages.length > 0 ? parsedPages : ['/dashboard'],
      authType,
      ...(githubRepoOwner ? { githubRepoOwner } : {}),
      ...(githubRepoName ? { githubRepoName } : {}),
      ...(githubBaseBranch ? { githubBaseBranch } : {}),
      ...(Object.keys(selectors).length > 0 ? { loginFieldSelectors: selectors } : {})
    };
    
    // Slight delay for animation effect
    setTimeout(() => {
      onStart(config);
    }, 600);
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 1.05 }}
      className="flex flex-col items-center justify-center min-h-screen p-6 py-12"
    >
      <div className="mb-10 text-center" style={{ paddingBottom: '32px' }}>
        <motion.div
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="flex justify-center mb-4"
        >
          <VibeAuditLogo size="xl" animated={true} />
        </motion.div>
        <motion.p
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="text-gray-400 text-sm mt-2 font-mono tracking-widest"
        >
          EXPLOIT. PATCH. PROTECT.
        </motion.p>
      </div>

      <div className="w-full max-w-xl space-y-6 pb-20">
        <AnimatePresence>
          {localError && (
            <motion.div 
              initial={{ opacity: 0, y: -10 }} 
              animate={{ opacity: 1, y: 0 }} 
              exit={{ opacity: 0, y: -10 }}
              className="bg-brand-red/20 border border-brand-red/50 text-brand-red px-4 py-3 rounded-md flex justify-between items-center"
            >
              <div className="font-mono text-sm">{localError}</div>
              <button onClick={() => setLocalError(null)} className="text-brand-red/50 hover:text-brand-red text-lg leading-none">&times;</button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Demo Preset */}
        <button
          type="button"
          onClick={loadShopVulnDemo}
          className="w-full text-left bg-brand-green/5 hover:bg-brand-green/10 border border-brand-green/20 hover:border-brand-green/40 rounded-md px-4 py-3 transition-all group flex items-center justify-between"
        >
          <div>
            <div className="text-xs font-mono text-brand-green font-bold uppercase tracking-widest">⚡ Load ShopVuln Demo</div>
            <div className="text-[10px] font-mono text-white/40 mt-0.5">shopvuln.vercel.app · includes GitHub PR integration</div>
          </div>
          <ChevronRight className="w-4 h-4 text-brand-green/50 group-hover:text-brand-green transition-colors" />
        </button>

        <GlassCard glowColor="none">
          <div className="space-y-6">
            {/* Target URL */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-white/50 uppercase tracking-wider">Target App URL</label>
              <div className="relative">
                <Terminal className="absolute left-3 top-3 w-5 h-5 text-white/30" />
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className={`w-full bg-black/50 border rounded-md py-2.5 pl-10 pr-4 text-white font-mono text-sm focus:outline-none transition-all ${url.length > 0 && !isUrlValid ? 'border-brand-red focus:border-brand-red focus:ring-1 focus:ring-brand-red' : 'border-white/10 focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50'}`}
                  placeholder="https://your-app.com"
                />
              </div>
              {url.length > 0 && !isUrlValid && <p className="text-[10px] text-brand-red font-mono uppercase tracking-wider mt-1">Invalid URL: must start with http:// or https://</p>}
            </div>

            {/* User A — Victim */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-white/50 uppercase tracking-wider flex flex-col">
                <span className="flex items-center gap-2 text-white/80"><User className="w-3.5 h-3.5" /> User A</span>
                <span className="text-[10px] text-brand-green mt-0.5">Victim Account (owns the data)</span>
              </label>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <input
                    type="email"
                    value={userAEmail}
                    onChange={(e) => setUserAEmail(e.target.value)}
                    className={`w-full bg-black/50 border rounded-md py-2 px-3 text-white font-mono text-sm focus:outline-none transition-all ${userAEmail.length > 0 && !isUserAEmailValid ? 'border-brand-red focus:border-brand-red focus:ring-1 focus:ring-brand-red' : 'border-white/10 focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50'}`}
                    placeholder="victim@yourapp.com"
                  />
                  {userAEmail.length > 0 && !isUserAEmailValid && <p className="text-[10px] text-brand-red font-mono uppercase tracking-wider mt-1">Must contain @</p>}
                </div>
                <div>
                  <input
                    type="password"
                    value={userAPassword}
                    onChange={(e) => setUserAPassword(e.target.value)}
                    className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-sm focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                    placeholder="password"
                  />
                </div>
              </div>
            </div>

            {/* User B — Attacker */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-white/50 uppercase tracking-wider flex flex-col">
                <span className="flex items-center gap-2 text-white/80"><UserX className="w-3.5 h-3.5" /> User B</span>
                <span className="text-[10px] text-brand-red mt-0.5">Attacker Account (should NOT have access)</span>
              </label>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <input
                    type="email"
                    value={userBEmail}
                    onChange={(e) => setUserBEmail(e.target.value)}
                    className={`w-full bg-black/50 border rounded-md py-2 px-3 text-white font-mono text-sm focus:outline-none transition-all ${userBEmail.length > 0 && !isUserBEmailValid ? 'border-brand-red focus:border-brand-red focus:ring-1 focus:ring-brand-red' : 'border-white/10 focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50'}`}
                    placeholder="attacker@yourapp.com"
                  />
                  {userBEmail.length > 0 && !isUserBEmailValid && <p className="text-[10px] text-brand-red font-mono uppercase tracking-wider mt-1">Must contain @</p>}
                </div>
                <div>
                  <input
                    type="password"
                    value={userBPassword}
                    onChange={(e) => setUserBPassword(e.target.value)}
                    className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-sm focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                    placeholder="password"
                  />
                </div>
              </div>
            </div>

            {/* Consent */}
            <div className="pt-4 border-t border-white/10">
              <label className="flex items-start gap-3 cursor-pointer group">
                <div className="relative flex items-start mt-0.5">
                  <input
                    type="checkbox"
                    className="peer sr-only"
                    checked={consent}
                    onChange={(e) => setConsent(e.target.checked)}
                  />
                  <div className="w-5 h-5 border-2 border-white/20 rounded peer-checked:bg-brand-green peer-checked:border-brand-green transition-all flex items-center justify-center">
                    <motion.svg
                      initial={false}
                      animate={{ opacity: consent ? 1 : 0 }}
                      className="w-3.5 h-3.5 text-black"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={3}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </motion.svg>
                  </div>
                </div>
                <span className="text-xs text-white/60 leading-relaxed group-hover:text-white/80 transition-colors">
                  I confirm I own or have explicit authorization to perform offensive security testing against this domain.
                </span>
              </label>
            </div>
          </div>
        </GlassCard>

        {/* Advanced Settings */}
        <GlassCard glowColor="none" className="p-4">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full flex items-center justify-between text-xs font-mono text-white/50 hover:text-white transition-colors uppercase tracking-wider"
          >
            <span className="flex items-center gap-2">⚙ Advanced Settings</span>
            {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          <AnimatePresence>
            {showAdvanced && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="space-y-5 overflow-hidden pt-5"
              >
                <div className="space-y-2">
                  <label className="text-[10px] font-mono text-white/40 uppercase tracking-wider">GitHub Repo Owner & Name <span className="text-white/20 normal-case tracking-normal">(optional)</span></label>
                  <p className="text-[10px] text-white/30 font-mono mb-2">Leave blank to skip PR generation — filled automatically by ShopVuln demo</p>
                  <div className="grid grid-cols-2 gap-4">
                    <input
                      type="text"
                      value={githubRepoOwner}
                      onChange={(e) => setGithubRepoOwner(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-xs focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                      placeholder="your-github-username"
                    />
                    <input
                      type="text"
                      value={githubRepoName}
                      onChange={(e) => setGithubRepoName(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-xs focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                      placeholder="your-repository-name"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Base Branch</label>
                  <input
                    type="text"
                    value={githubBaseBranch}
                    onChange={(e) => setGithubBaseBranch(e.target.value)}
                    className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-xs focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                    placeholder="main"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Login Path</label>
                    <input
                      type="text"
                      value={loginPath}
                      onChange={(e) => setLoginPath(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-xs focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                      placeholder="/login"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-mono text-white/40 uppercase tracking-wider">Auth Type</label>
                    <select
                      value={authType}
                      onChange={(e) => setAuthType(e.target.value as 'auto'|'cookie'|'jwt')}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-xs focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all appearance-none"
                    >
                      <option value="auto">Auto Detect</option>
                      <option value="cookie">Cookie</option>
                      <option value="jwt">JWT</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-mono text-white/40 uppercase tracking-wider flex justify-between">
                    <span>Pages to Crawl</span>
                    <span className="text-white/20 normal-case tracking-normal">One path per line</span>
                  </label>
                  <textarea
                    value={pagesToCrawl}
                    onChange={(e) => setPagesToCrawl(e.target.value)}
                    rows={3}
                    className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-3 text-white font-mono text-xs focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all resize-none custom-scrollbar leading-relaxed"
                    placeholder="/dashboard&#10;/orders&#10;/profile"
                  />
                  <p className="text-[10px] text-white/30 font-mono mt-1">Tip: Enter one path per line, or separate with commas</p>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-mono text-white/40 uppercase tracking-wider flex justify-between">
                    <span>Login Field Selectors</span>
                    <span className="text-white/20 normal-case tracking-normal">Leave blank for auto-detection</span>
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    <input
                      type="text"
                      value={emailSelector}
                      onChange={(e) => setEmailSelector(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-2 text-white font-mono text-[10px] focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                      placeholder="input[type=email]"
                    />
                    <input
                      type="text"
                      value={passwordSelector}
                      onChange={(e) => setPasswordSelector(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-2 text-white font-mono text-[10px] focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                      placeholder="input[type=password]"
                    />
                    <input
                      type="text"
                      value={submitSelector}
                      onChange={(e) => setSubmitSelector(e.target.value)}
                      className="w-full bg-black/50 border border-white/10 rounded-md py-2 px-2 text-white font-mono text-[10px] focus:outline-none focus:border-brand-green/50 focus:ring-1 focus:ring-brand-green/50 transition-all"
                      placeholder="button[type=submit]"
                    />
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </GlassCard>

        <button
          disabled={!isReady && !isScanning}
          onClick={handleSubmit}
          className={`w-full font-bold uppercase tracking-widest py-4 rounded-md transition-all duration-300 ${
            isScanning
              ? 'bg-brand-green/50 text-black shadow-[0_0_20px_rgba(0,255,102,0.4)] animate-pulse'
              : isReady 
              ? 'bg-brand-green text-black hover:bg-[#00e63a] hover:shadow-[0_0_20px_rgba(0,255,102,0.4)] focus:ring-4 focus:ring-brand-green/30' 
              : 'bg-white/5 text-white/20 cursor-not-allowed border border-white/5'
          }`}
        >
          {isScanning ? 'Validating...' : 'Launch Security Scan'}
        </button>

        {/* Scan History */}
        {history.length > 0 && (
          <GlassCard glowColor="none" className="p-4">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-mono text-white/50 uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-3.5 h-3.5" /> Scan History
              </span>
              <button
                onClick={() => { localStorage.removeItem('vibeaudit_history'); setHistory([]); }}
                className="text-[10px] font-mono text-white/30 hover:text-white/60 transition-colors flex items-center gap-1"
              >
                <Trash2 className="w-3 h-3" /> Clear All
              </button>
            </div>

            {(() => {
              const groups: Record<string, ScanHistoryEntry[]> = {};
              history.forEach((e) => {
                const g = getDateGroup(e.timestamp);
                if (!groups[g]) groups[g] = [];
                groups[g].push(e);
              });

              return Object.entries(groups).map(([group, entries]) => (
                <div key={group} className="mb-3 last:mb-0">
                  <div className="text-[10px] font-mono text-white/30 uppercase tracking-wider mb-2">{group}</div>
                  <div className="space-y-1.5">
                    {entries.map((entry) => {

                      const truncatedUrl = entry.id;
                      const detail = entry.status === 'vulnerable' ? 'Vulnerable' : 'Clean';

                      return (
                        <button
                          key={entry.id}
                          onClick={() => setSelectedEntry(entry)}
                          className="w-full text-left bg-white/[0.02] hover:bg-white/[0.05] border border-white/5 rounded-md px-3 py-2.5 transition-all group"
                        >
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-mono text-white/70 truncate flex-1 group-hover:text-white transition-colors">{truncatedUrl}</span>

                            <span className="text-[10px] font-mono text-white/20 shrink-0">{timeAgo(entry.timestamp)}</span>
                            <ChevronRight className="w-3.5 h-3.5 text-white/15 group-hover:text-white/40 transition-colors shrink-0" />
                          </div>
                          <div className="ml-[72px] mt-1">
                            <span className="text-[10px] font-mono text-white/25 truncate block">{detail}</span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ));
            })()}
          </GlassCard>
        )}
      </div>

      {/* History Modal */}
      {selectedEntry && (
        <ScanHistoryModal
          entry={selectedEntry}
          onClose={() => setSelectedEntry(null)}
          onDelete={(id) => {
            const updated = history.filter(h => h.id !== id);
            setHistory(updated);
            localStorage.setItem('vibeaudit_history', JSON.stringify(updated));
            setSelectedEntry(null);
          }}
        />
      )}
    </motion.div>
  );
}
