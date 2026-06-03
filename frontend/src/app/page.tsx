"use client";

import React from 'react';
import { AnimatePresence } from 'framer-motion';
import { useVibeScanner } from '@/hooks/useVibeScanner';
import { ScanConfig } from '@/types';
import { useEffect } from 'react';

import { LandingStage } from '@/components/stages/LandingStage';
import { PreflightStage } from '@/components/stages/PreflightStage';
import { CrawlerStage } from '@/components/stages/CrawlerStage';
import { AttackStage } from '@/components/stages/AttackStage';
import { AIPatchStage } from '@/components/stages/AIPatchStage';
import { VictoryStage } from '@/components/stages/VictoryStage';

export default function Home() {
  const { activeStage, setActiveStage, events, isClean, startScan, error, endpointProgress } = useVibeScanner();

  useEffect(() => {
    try {
      const raw = localStorage.getItem('vibeaudit_active_scan');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Date.now() - parsed.startedAt <= 10 * 60 * 1000) {
          setActiveStage('preflight');
        }
      }
    } catch { /* ignore */ }
  }, [setActiveStage]);

  const handleStart = (config: ScanConfig) => {
    startScan(config);
  };

  return (
    <main className="min-h-screen selection:bg-brand-green/30 selection:text-brand-green">
      <AnimatePresence mode="wait">
        {activeStage === 'landing' && (
          <LandingStage key="landing" onStart={handleStart} error={error} />
        )}
        
        {activeStage === 'preflight' && (
          <PreflightStage key="preflight" events={events} />
        )}
        
        {activeStage === 'crawler' && (
          <CrawlerStage key="crawler" events={events} />
        )}
        
        {activeStage === 'attack' && (
          <AttackStage key="attack" events={events} endpointProgress={endpointProgress} />
        )}
        
        {(activeStage === 'ai' || activeStage === 'github') && (
          <AIPatchStage key="ai" events={events} />
        )}

        {(activeStage === 'verify' || activeStage === 'done' || activeStage === 'summary') && (
          <VictoryStage key="victory" events={events} isClean={isClean} />
        )}
      </AnimatePresence>
    </main>
  );
}
