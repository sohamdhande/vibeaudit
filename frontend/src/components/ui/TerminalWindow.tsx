import React, { useEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { cn } from '@/lib/utils';
import { TerminalLine, TerminalLineData } from './TerminalLine';
import { VibeAuditLogo } from '../VibeAuditLogo';

interface TerminalWindowProps {
  lines: TerminalLineData[];
  className?: string;
  accentColor?: 'green' | 'red' | 'blue';
  title?: string;
}

export function TerminalWindow({ lines, className, accentColor = 'green', title = 'TERMINAL' }: TerminalWindowProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const [isAutoScrollEnabled, setIsAutoScrollEnabled] = useState(true);
  
  const virtualizer = useVirtualizer({
    count: lines.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 24, // Expected height per row
    overscan: 20,
  });

  const handleScroll = () => {
    if (!parentRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = parentRef.current;
    
    // If we are within 100px of the bottom, enable auto-scroll
    const isAtBottom = scrollHeight - scrollTop - clientHeight <= 100;
    setIsAutoScrollEnabled(isAtBottom);
  };

  // Auto-scroll when new lines arrive
  useEffect(() => {
    if (isAutoScrollEnabled && lines.length > 0) {
      setTimeout(() => {
        virtualizer.scrollToIndex(lines.length - 1, { align: 'end', behavior: 'smooth' });
      }, 0);
    }
  }, [lines.length, isAutoScrollEnabled, virtualizer]);

  let borderClass = 'border-brand-green/30';
  let titleClass = 'text-brand-green';
  if (accentColor === 'red') {
    borderClass = 'border-brand-red/30';
    titleClass = 'text-brand-red';
  } else if (accentColor === 'blue') {
    borderClass = 'border-blue-500/30';
    titleClass = 'text-blue-500';
  }

  return (
    <div className={cn(
      'flex flex-col bg-[#050505] border rounded-md overflow-hidden font-mono text-sm shadow-2xl',
      borderClass,
      className
    )}>
      {/* Terminal Header */}
      <div className={cn(
        'flex items-center justify-between px-4 py-2 border-b bg-[#0a0a0a]',
        borderClass.replace('/30', '/20')
      )}>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500/50" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
          <div className="w-3 h-3 rounded-full bg-green-500/50" />
          <div className="ml-1" style={{ padding: '4px' }}>
            <VibeAuditLogo size="icon" animated={false} className="opacity-60" />
          </div>
        </div>
        <div className={cn('text-xs tracking-widest font-bold opacity-70', titleClass)}>
          {title}
        </div>
        <div className="w-10 flex justify-end">
          {!isAutoScrollEnabled && (
            <div className="w-2 h-2 rounded-full bg-white/20 animate-pulse" title="Auto-scroll paused" />
          )}
        </div>
      </div>

      {/* Terminal Body */}
      <div 
        ref={parentRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto relative"
      >
        {lines.length === 0 && (
          <div className="text-white/30 italic p-4">Waiting for input...</div>
        )}
        
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const line = lines[virtualRow.index];
            // Typing effect only for the very last item
            const isNew = virtualRow.index === lines.length - 1;
            
            return (
              <TerminalLine
                key={line.id}
                line={line}
                isNew={isNew}
                virtualRowStart={virtualRow.start}
                measureRef={virtualizer.measureElement}
                index={virtualRow.index}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}
