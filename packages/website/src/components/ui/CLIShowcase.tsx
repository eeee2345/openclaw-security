'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import BrandLogo from './BrandLogo';

/* ─── Tab definitions ─── */

const tabs = [
  { id: 'scan', label: 'Scan' },
  { id: 'guard', label: 'Guard' },
  { id: 'chat', label: 'Chat' },
] as const;

type TabId = (typeof tabs)[number]['id'];

/* ─── Line types for structured rendering ─── */

interface Line {
  text: string;
  color?: string;
}

const c = {
  cmd: 'text-brand-sage',
  ok: 'text-[#2ED573]',
  warn: 'text-[#FBBF24]',
  err: 'text-[#EF4444]',
  dim: 'text-text-tertiary',
  muted: 'text-text-muted',
  base: 'text-text-secondary',
  bright: 'text-text-primary',
  sage: 'text-brand-sage',
};

/* ─── CLI content for each tab ─── */

const tabContent: Record<TabId, Line[]> = {
  scan: [
    { text: '$ panguard scan --deep', color: c.cmd },
    { text: '' },
    { text: 'Scan Complete. 3 issues found.              Score: 87/100 (B+)', color: c.bright },
    { text: '' },
    { text: '  HIGH    Open SSH on 0.0.0.0', color: c.err },
    { text: "          $ sudo sed -i 's/0.0.0.0/127.0.0.1/' /etc/ssh/sshd_config", color: c.dim },
    { text: '' },
    { text: '  MEDIUM  TLS 1.1 detected', color: c.warn },
    { text: "          $ sudo sed -i 's/TLSv1.1/TLSv1.3/' /etc/nginx/nginx.conf", color: c.dim },
    { text: '' },
    { text: '  LOW     Kernel outdated                  Noted', color: c.base },
    { text: '' },
    { text: '  3 issues found \u00B7 0 auto-fixed', color: c.muted },
    { text: '' },
    { text: '  \u26A1 Upgrade to Solo ($9/mo) \u2192 panguard scan --fix', color: c.sage },
  ],
  guard: [
    { text: '$ panguard guard start', color: c.cmd },
    { text: 'Panguard Guard v2.1.0 -- Starting...', color: c.bright },
    { text: '' },
    { text: '  Layer 1 (Sigma Rules)    LOADED  3,155 rules', color: c.ok },
    { text: '  Layer 2 (Local AI)       READY   Ollama connected', color: c.ok },
    { text: '  Layer 3 (Cloud AI)       STANDBY', color: c.base },
    { text: '  Threat Cloud Upload      ENABLED', color: c.ok },
    { text: '' },
    { text: '[15:32:05] Threat detected', color: c.err },
    { text: '  Type: SSH brute-force', color: c.base },
    { text: '  Source: 103.xx.xx.xx (CN)', color: c.base },
    { text: '  Severity: HIGH', color: c.err },
    { text: '  Action: IP blocked', color: c.ok },
    { text: '' },
    { text: '[15:32:06] LINE notification sent', color: c.sage },
    { text: '' },
    { text: 'Status: 2,847 events | 12 threats blocked | 0 critical', color: c.sage },
  ],
  chat: [
    { text: '$ panguard chat', color: c.cmd },
    { text: '' },
    { text: 'You: Is my server safe right now?', color: c.bright },
    { text: '' },
    { text: "Panguard: Yes. Here's your current status:", color: c.sage },
    { text: '' },
    { text: '  Guard uptime:    14d 6h 32m', color: c.ok },
    { text: '  Threats blocked: 2,847 (last 24h)', color: c.ok },
    { text: '  Security score:  94/100 (A)', color: c.ok },
    { text: '  Open issues:     0 critical, 1 medium', color: c.warn },
    { text: '' },
    { text: 'You: What was the medium issue?', color: c.bright },
    { text: '' },
    { text: 'Panguard: TLS 1.1 is still enabled on port 443.', color: c.sage },
    { text: '  Recommendation: Disable TLS 1.1 in your nginx config.', color: c.sage },
    { text: '  I can generate the fix. Want me to?', color: c.sage },
  ],
};

/* ═══════════════════════  Component  ═══════════════════════ */

export default function CLIShowcase() {
  const [activeTab, setActiveTab] = useState<TabId>('scan');

  return (
    <div className="relative max-w-4xl mx-auto">
      {/* Terminal chrome */}
      <div className="bg-[#1C1814] rounded-t-xl border border-border border-b-0 px-4 py-3 flex items-center gap-3">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#FBBF24]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#2ED573]" />
        </div>
        <div className="flex items-center gap-2 ml-3">
          <BrandLogo size={14} className="text-brand-sage" />
          <span className="text-xs font-mono text-text-secondary">PANGUARD [-] AI CLI v2.1.0</span>
        </div>
        <span className="ml-auto text-[10px] font-mono text-text-muted hidden sm:block">
          SYSTEM: ONLINE | CPU: 12% | MEM: 4GB | LATENCY: 2ms
        </span>
      </div>

      {/* Tab bar */}
      <div className="bg-[#1A1614] border-x border-border flex gap-0 overflow-x-auto scrollbar-hide">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`relative px-5 py-2.5 text-xs font-mono font-medium transition-colors shrink-0 ${
                isActive
                  ? 'text-brand-sage bg-brand-sage/10'
                  : 'text-text-muted hover:text-text-secondary'
              }`}
            >
              {tab.label}
              {isActive && (
                <motion.div
                  layoutId="cli-tab-indicator"
                  className="absolute bottom-0 left-0 right-0 h-[2px] bg-brand-sage"
                  transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                />
              )}
            </button>
          );
        })}
      </div>

      {/* Terminal body */}
      <div className="bg-[#1A1614] rounded-b-xl border border-border border-t-0 p-5 sm:p-6 font-mono text-[12px] sm:text-[13px] leading-[1.7] min-h-[380px] overflow-x-auto">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.15 }}
          >
            {tabContent[activeTab].map((line, i) => {
              if (!line.text) return <div key={i} className="h-3" />;
              return (
                <div key={i} className={`${line.color || c.base} whitespace-pre`}>
                  {line.text}
                </div>
              );
            })}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Ambient glow */}
      <div className="absolute -inset-8 bg-brand-sage/3 rounded-3xl blur-[60px] -z-10" />
    </div>
  );
}
