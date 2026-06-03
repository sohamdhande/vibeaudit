import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface TerminalLineData {
  id: string;
  content: string | React.ReactNode;
  timestamp: number;
  type?: 'log' | 'success' | 'error' | 'warning' | 'data';
}

interface TerminalLineProps {
  line: TerminalLineData;
  isNew: boolean;
  virtualRowStart: number;
  measureRef?: (node: Element | null) => void;
  index?: number;
}

function parseContentToReact(content: string) {
  const parts = content.split(/(\[[^\]]+\])/g);
  return parts.map((part, i) => {
    if (part.startsWith('[') && part.endsWith(']')) {
      return <span key={i} className="opacity-50">{part}</span>;
    }
    return part;
  });
}

export const TerminalLine = React.memo(function TerminalLine({ line, isNew, virtualRowStart, measureRef, index }: TerminalLineProps) {
  const [displayedContent, setDisplayedContent] = useState<string | React.ReactNode>(
    isNew && typeof line.content === 'string' ? '' : line.content
  );

  useEffect(() => {
    if (isNew && typeof line.content === 'string') {
      let currentIndex = 0;
      const fullText = line.content;
      
      const interval = setInterval(() => {
        if (currentIndex <= fullText.length) {
          setDisplayedContent(fullText.slice(0, currentIndex));
          currentIndex += 2; // Type 2 chars at a time for speed
        } else {
          clearInterval(interval);
          setDisplayedContent(fullText);
        }
      }, 10);
      
      return () => clearInterval(interval);
    } else {
      setDisplayedContent(line.content);
    }
  }, [isNew, line.content]);

  let colorClass = 'text-white/80';
  if (line.type === 'success') colorClass = 'text-brand-green';
  else if (line.type === 'error') colorClass = 'text-brand-red';
  else if (line.type === 'warning') colorClass = 'text-yellow-400';
  else if (line.type === 'data') colorClass = 'text-blue-400';

  const date = new Date(line.timestamp);
  const timeString = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}.${date.getMilliseconds().toString().padStart(3, '0')}`;

  return (
    <div
      ref={measureRef}
      data-index={index}
      className={cn('absolute top-0 left-0 w-full whitespace-pre-wrap break-all px-4 flex gap-4', colorClass)}
      style={{
        transform: `translateY(${virtualRowStart}px)`,
      }}
    >
      <span className="text-white/30 shrink-0 select-none">[{timeString}]</span>
      <span className="flex-1">
        {typeof displayedContent === 'string' ? (
          <span>{parseContentToReact(displayedContent)}</span>
        ) : (
          displayedContent
        )}
      </span>
    </div>
  );
});
