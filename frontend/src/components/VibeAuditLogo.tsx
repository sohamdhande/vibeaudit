import React from 'react';

type LogoSize = 'icon' | 'sm' | 'md' | 'lg' | 'xl';

interface VibeAuditLogoProps {
  /** icon: 32px, sm: 120px, md: 200px, lg: 300px */
  size?: LogoSize;
  /** When true the red scan line animates continuously */
  animated?: boolean;
  /** When true, renders text in dark colors for light backgrounds */
  lightMode?: boolean;
  className?: string;
}

const SIZE_MAP: Record<LogoSize, { width: number; height: number }> = {
  icon: { width: 32, height: 32 },
  sm:   { width: 120, height: 60 },
  md:   { width: 200, height: 100 },
  lg:   { width: 300, height: 150 },
  xl:   { width: 460, height: 230 },
};

/**
 * Inline SVG logo for VibeAudit.
 * Works in ALL contexts (DOM, SSR, img-tag fallback not needed)
 * because the entire SVG is part of the React tree.
 *
 * Uses React.useId() for collision-safe unique IDs when
 * multiple logo instances are rendered simultaneously.
 */
export function VibeAuditLogo({
  size = 'md',
  animated = true,
  lightMode = false,
  className,
}: VibeAuditLogoProps) {
  const { width, height } = SIZE_MAP[size];
  const isIconOnly = size === 'icon';

  // Unique IDs per instance to avoid collisions when multiple logos render
  const uid = React.useId().replace(/:/g, '');
  const clipId = `vaClip-${uid}`;
  const maskId = `vaMask-${uid}`;
  const scanId = `vaScan-${uid}`;
  const animName = `vaScanAnim-${uid}`;

  if (isIconOnly) {
    return (
      <svg
        width={width}
        height={height}
        viewBox="0 0 32 32"
        xmlns="http://www.w3.org/2000/svg"
        className={className}
        role="img"
        aria-label="VibeAudit"
      >
        {animated && (
          <style>{`
            #${scanId} {
              animation: ${animName} 2s linear infinite;
            }
            @keyframes ${animName} {
              0%   { transform: translateY(-10px); opacity: 0; }
              10%  { opacity: 1; }
              90%  { opacity: 1; }
              100% { transform: translateY(14px); opacity: 0; }
            }
          `}</style>
        )}
        {/* Shield */}
        <path d="M16 2 L30 8 L30 18 Q30 27 16 31 Q2 27 2 18 L2 8 Z" fill="#0f1117" stroke="#2a2f3e" strokeWidth="1" />
        <path d="M16 5 L27 10 L27 18 Q27 25 16 28 Q5 25 5 18 L5 10 Z" fill="none" stroke="#1e2435" strokeWidth="0.5" />
        {/* Circuit traces */}
        <line x1="7" y1="17" x2="25" y2="17" stroke="#475569" strokeWidth="0.5" strokeDasharray="2 1" />
        <line x1="11" y1="11" x2="11" y2="23" stroke="#475569" strokeWidth="0.5" />
        <line x1="21" y1="11" x2="21" y2="23" stroke="#475569" strokeWidth="0.5" />
        <circle cx="11" cy="17" r="1" fill="#475569" />
        <circle cx="21" cy="17" r="1" fill="#475569" />
        <circle cx="16" cy="11" r="1" fill="#475569" />
        <circle cx="16" cy="23" r="1" fill="#475569" />
        {/* Scan line */}
        <clipPath id={clipId}>
          <path d="M5 9 L27 9 L27 18 Q27 25 16 28 Q5 25 5 18 Z" />
        </clipPath>
        {animated && (
          <g clipPath={`url(#${clipId})`}>
            <g id={scanId}>
              <line x1="6" y1="17" x2="26" y2="17" stroke="#ef4444" strokeWidth="1" opacity="1" />
              <rect x="6" y="14" width="20" height="6" fill="#ef4444" opacity="0.12" />
            </g>
          </g>
        )}
        {/* Lock */}
        <rect x="12" y="16" width="8" height="6" rx="1" fill="#1a2035" stroke="#3d4a6b" strokeWidth="0.5" />
        <path d="M13.5 16 Q13.5 13 16 13 Q18.5 13 18.5 16" fill="none" stroke="#3d4a6b" strokeWidth="0.7" strokeLinecap="round" />
        <circle cx="16" cy="19" r="1" fill="#ef4444" opacity="0.5" />
      </svg>
    );
  }

  // Full logo: shield + wordmark
  return (
    <svg
      width={width}
      height={height}
      viewBox="0 0 680 340"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="VibeAudit"
    >
      {animated && (
        <style>{`
          #${scanId} {
            animation: ${animName} 2s linear infinite;
          }
          @keyframes ${animName} {
            0%   { transform: translateY(-60px); opacity: 0; }
            10%  { opacity: 1; }
            90%  { opacity: 1; }
            100% { transform: translateY(60px); opacity: 0; }
          }
        `}</style>
      )}
      <defs>
        <mask id={maskId} maskUnits="userSpaceOnUse">
          <rect x="0" y="0" width="680" height="340" fill="white" />
          <rect x="307" y="94.818" width="133.227" height="64.455" fill="black" rx="2" />
          <rect x="307" y="149.818" width="164.534" height="64.455" fill="black" rx="2" />
          <rect x="307" y="218.636" width="318.66" height="18.091" fill="black" rx="2" />
          <rect x="551.29" y="124.818" width="13.419" height="14.455" fill="black" rx="2" />
        </mask>
      </defs>

      {/* Shield body */}
      <g transform="translate(186,60)">
        {/* Outer shield */}
        <path d="M54 0 L108 22 L108 72 Q108 118 54 138 Q0 118 0 72 L0 22 Z" fill="#0f1117" stroke="#2a2f3e" strokeWidth="2" />
        {/* Inner ring */}
        <path d="M54 10 L98 28 L98 72 Q98 110 54 126 Q10 110 10 72 L10 28 Z" fill="none" stroke="#1e2435" strokeWidth="1" />

        {/* Circuit traces */}
        <line x1="18" y1="69" x2="90" y2="69" stroke="#475569" strokeWidth="1" strokeDasharray="4 2" />
        <line x1="32" y1="42" x2="32" y2="96" stroke="#475569" strokeWidth="1" />
        <line x1="76" y1="42" x2="76" y2="96" stroke="#475569" strokeWidth="1" />
        {/* Node dots */}
        <circle cx="32" cy="69" r="2.5" fill="#475569" />
        <circle cx="76" cy="69" r="2.5" fill="#475569" />
        <circle cx="54" cy="42" r="2.5" fill="#475569" />
        <circle cx="54" cy="96" r="2.5" fill="#475569" />

        {/* Scan line */}
        <clipPath id={clipId}>
          <path d="M12 26 L96 26 L96 74 Q96 112 54 128 Q12 112 12 74 Z" />
        </clipPath>
        {animated && (
          <g clipPath={`url(#${clipId})`} overflow="hidden">
            <g id={scanId}>
              <line x1="14" y1="69" x2="94" y2="69" stroke="#ef4444" strokeWidth="1.5" opacity="1" />
              <rect x="14" y="62" width="80" height="14" fill="#ef4444" opacity="0.12" />
            </g>
          </g>
        )}

        {/* Lock icon */}
        <rect x="43" y="68" width="22" height="18" rx="2" fill="#1a2035" stroke="#3d4a6b" strokeWidth="1.2" />
        <path d="M47 68 Q47 58 54 58 Q61 58 61 68" fill="none" stroke="#3d4a6b" strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="54" cy="77" r="2.5" fill="#ef4444" opacity="0.37" />

        {/* Top edge highlight */}
        <path d="M54 3 L100 23" stroke="#3a4260" strokeWidth="1" strokeLinecap="round" />
        <path d="M54 3 L8 23" stroke="#3a4260" strokeWidth="1" strokeLinecap="round" />
      </g>

      {/* Wordmark */}
      <text x="311" y="145" fontSize="52" fill={lightMode ? "#534AB7" : "#f1f5f9"} fontFamily="ui-monospace, 'SF Mono', Consolas, monospace" fontWeight="700">Vibe</text>
      <text x="311" y="200" fontSize="52" fill="#ef4444" fontFamily="ui-monospace, 'SF Mono', Consolas, monospace" fontWeight="700">Audit</text>

      {/* Divider */}
      <line x1="311" y1="212" x2="565" y2="212" stroke="#2a2f3e" strokeWidth="1" mask={`url(#${maskId})`} />

      {/* Tagline */}
      <text x="311" y="232" fontSize="12" fill="#64748b" fontFamily="ui-monospace, 'SF Mono', Consolas, monospace">
        BOLA / IDOR  ·  SECURITY SCANNER  ·  AI-POWERED
      </text>

      {/* Alert badge */}
      <circle cx="558" cy="131" r="7" fill="#ef4444" opacity="0.37" />
      <text x="558" y="135" textAnchor="middle" fontFamily="ui-monospace,monospace" fontSize="9" fontWeight="700" fill="white">!</text>
    </svg>
  );
}
