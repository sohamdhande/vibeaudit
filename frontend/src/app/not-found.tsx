"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Shield, ArrowLeft } from "lucide-react";

export default function NotFound() {
  const router = useRouter();
  const REDIRECT_DELAY = 3.55;
  const [countdown, setCountdown] = useState(REDIRECT_DELAY);

  useEffect(() => {
    const interval = setInterval(() => {
      setCountdown((prev) => {
        const next = prev - 0.01;
        return next > 0 ? parseFloat(next.toFixed(2)) : 0;
      });
    }, 10);

    const timeout = setTimeout(() => {
      router.push("/");
    }, REDIRECT_DELAY * 1000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, [router]);

  const progressPercent = ((REDIRECT_DELAY - countdown) / REDIRECT_DELAY) * 100;

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden">
      {/* Animated background scanlines */}
      <div className="pointer-events-none absolute inset-0 z-0 overflow-hidden">
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.15) 2px, rgba(0,255,65,0.15) 4px)",
          }}
        />
        <motion.div
          className="absolute left-0 right-0 h-[2px] bg-brand-green/20"
          initial={{ top: "-2px" }}
          animate={{ top: "100%" }}
          transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
        />
      </div>

      {/* Glowing orb behind the 404 */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] rounded-full bg-brand-red/[0.04] blur-[120px] pointer-events-none" />

      {/* Content */}
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="relative z-10 flex flex-col items-center text-center"
      >
        {/* Shield icon */}
        <motion.div
          initial={{ scale: 0, rotate: -180 }}
          animate={{ scale: 1, rotate: 0 }}
          transition={{ delay: 0.1, type: "spring", stiffness: 200, damping: 15 }}
          className="inline-flex items-center justify-center p-4 mb-8 rounded-full bg-white/5 border border-brand-red/20 glow-red"
        >
          <Shield className="w-10 h-10 text-brand-red" />
        </motion.div>

        {/* 404 number */}
        <motion.h1
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="text-[120px] sm:text-[160px] font-black leading-none tracking-tighter text-glow-red text-brand-red/90 select-none"
          style={{ fontFamily: "var(--font-geist-sans)" }}
        >
          404
        </motion.h1>

        {/* Message */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.4 }}
          className="mt-2 space-y-3"
        >
          <p className="text-sm font-mono text-white/60 uppercase tracking-[0.3em]">
            Endpoint Not Found
          </p>
          <p className="text-xs font-mono text-white/30 max-w-md leading-relaxed">
            The route you requested does not exist on this server.
            <br />
            No vulnerability to report here.
          </p>
        </motion.div>

        {/* Countdown timer */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="mt-10 flex flex-col items-center gap-4 w-full max-w-xs"
        >
          {/* Progress bar */}
          <div className="w-full h-[2px] bg-white/5 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-brand-green/70 rounded-full"
              initial={{ width: "0%" }}
              animate={{ width: "100%" }}
              transition={{ duration: REDIRECT_DELAY, ease: "linear" }}
            />
          </div>

          <p className="text-[10px] font-mono text-white/30 tracking-widest uppercase">
            Redirecting in{" "}
            <span className="text-brand-green/80 tabular-nums">
              {countdown.toFixed(2)}s
            </span>
          </p>

          {/* Manual redirect button */}
          <button
            onClick={() => router.push("/")}
            className="flex items-center gap-2 text-xs font-mono text-white/40 hover:text-brand-green transition-colors group mt-2"
          >
            <ArrowLeft className="w-3.5 h-3.5 group-hover:-translate-x-1 transition-transform" />
            Return to Dashboard
          </button>
        </motion.div>
      </motion.div>

      {/* Bottom terminal-style line */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.8 }}
        className="absolute bottom-6 text-[10px] font-mono text-white/15 tracking-widest"
      >
        VIBEAUDIT — HTTP 404
      </motion.div>
    </div>
  );
}
