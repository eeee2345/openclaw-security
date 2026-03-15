'use client';

import { useState, useCallback } from 'react';
import { useTranslations } from 'next-intl';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowRight } from 'lucide-react';
import { Link } from '@/navigation';
import { ShieldIcon, ScanIcon } from '@/components/ui/BrandIcons';

interface ScanFinding {
  id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  location?: string;
}

interface ScanReport {
  skillName: string | null;
  riskScore: number;
  riskLevel: string;
  findings: ScanFinding[];
  checks: Array<{ status: string; label: string }>;
  durationMs: number;
}

interface ScanResponse {
  ok: boolean;
  error?: string;
  data?: {
    report: ScanReport;
    cached: boolean;
    contentHash: string;
    source: string;
    scannedAt: string;
  };
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  info: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-emerald-400',
};

function RiskGauge({ score, level }: { score: number; level: string }) {
  const color = RISK_COLORS[level] ?? 'text-gray-400';
  const barColor =
    level === 'CRITICAL'
      ? 'bg-red-400'
      : level === 'HIGH'
        ? 'bg-orange-400'
        : level === 'MEDIUM'
          ? 'bg-yellow-400'
          : 'bg-emerald-400';

  return (
    <div className="flex items-center gap-4">
      <div className="flex-1">
        <div className="h-2 rounded-full bg-surface-2 overflow-hidden">
          <motion.div
            className={`h-full rounded-full ${barColor}`}
            initial={{ width: 0 }}
            animate={{ width: `${score}%` }}
            transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          />
        </div>
      </div>
      <div className="text-right shrink-0">
        <span className={`text-2xl font-extrabold ${color}`}>{score}</span>
        <span className="text-sm text-text-muted">/100</span>
      </div>
      <span
        className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${color} ${barColor}/10 border border-current/20`}
      >
        {level}
      </span>
    </div>
  );
}

export default function SkillScanner() {
  const t = useTranslations('home.scanner');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [expanded, setExpanded] = useState(false);

  const handleScan = useCallback(async () => {
    const trimmed = url.trim();
    if (!trimmed || loading) return;

    setLoading(true);
    setResult(null);
    setExpanded(false);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });
      const data: ScanResponse = await res.json();
      setResult(data);
      if (data.ok && data.data && data.data.report.riskLevel !== 'LOW') {
        setExpanded(true);
      }
    } catch {
      setResult({ ok: false, error: 'Network error. Please try again.' });
    } finally {
      setLoading(false);
    }
  }, [url, loading]);

  const report = result?.ok ? result.data?.report : null;
  const meta = result?.ok ? result.data : null;

  return (
    <section className="relative px-5 sm:px-6 py-16 sm:py-20 border-b border-border/30">
      <div className="max-w-[700px] mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <p className="text-[11px] uppercase tracking-[0.15em] text-panguard-green font-semibold mb-3">
            {t('overline')}
          </p>
          <h2 className="text-2xl sm:text-3xl font-bold text-text-primary">{t('title')}</h2>
          <p className="text-sm text-text-secondary mt-3 max-w-lg mx-auto">{t('subtitle')}</p>
        </div>

        {/* Input */}
        <div className="flex gap-2">
          <div className="relative flex-1">
            <ScanIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder={t('placeholder')}
              className="w-full bg-surface-1 border border-border rounded-xl pl-10 pr-4 py-3.5 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-panguard-green transition-colors"
              disabled={loading}
            />
          </div>
          <button
            onClick={handleScan}
            disabled={loading || !url.trim()}
            className="shrink-0 bg-panguard-green text-white font-semibold rounded-xl px-6 py-3.5 text-sm hover:bg-panguard-green-light transition-all duration-200 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {loading ? (
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <ShieldIcon className="w-4 h-4" />
            )}
            {t('scanBtn')}
          </button>
        </div>

        {/* Error */}
        {result && !result.ok && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-4 bg-red-400/10 border border-red-400/30 rounded-xl p-4 text-sm text-red-400"
          >
            {result.error}
          </motion.div>
        )}

        {/* Result */}
        <AnimatePresence>
          {report && meta && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
              className="mt-6 bg-surface-1 border border-border rounded-2xl overflow-hidden"
            >
              {/* Report header */}
              <div className="p-5 border-b border-border">
                <div className="flex items-center justify-between mb-1">
                  <h3 className="text-sm font-bold text-text-primary">
                    {report.skillName ?? 'Unknown Skill'}
                  </h3>
                  <div className="flex items-center gap-2 text-[10px] text-text-muted">
                    {meta.cached && (
                      <span className="bg-panguard-green/10 text-panguard-green px-2 py-0.5 rounded-full">
                        {t('cached')}
                      </span>
                    )}
                    <span>{report.durationMs}ms</span>
                  </div>
                </div>
                <p className="text-[11px] text-text-muted mb-4">{meta.source}</p>
                <RiskGauge score={report.riskScore} level={report.riskLevel} />
              </div>

              {/* Checks summary */}
              <div className="px-5 py-3 border-b border-border bg-surface-2/30">
                <div className="flex flex-wrap gap-2">
                  {report.checks.map((check) => (
                    <span
                      key={check.label}
                      className={`inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border ${
                        check.status === 'pass'
                          ? 'text-emerald-400 border-emerald-400/30 bg-emerald-400/5'
                          : check.status === 'fail'
                            ? 'text-red-400 border-red-400/30 bg-red-400/5'
                            : check.status === 'warn'
                              ? 'text-yellow-400 border-yellow-400/30 bg-yellow-400/5'
                              : 'text-gray-400 border-gray-400/30 bg-gray-400/5'
                      }`}
                    >
                      {check.status === 'pass'
                        ? '\u2713'
                        : check.status === 'fail'
                          ? '\u2717'
                          : '\u26A0'}{' '}
                      {check.label}
                    </span>
                  ))}
                </div>
              </div>

              {/* Findings */}
              {report.findings.length > 0 && (
                <div className="px-5 py-4">
                  <button
                    onClick={() => setExpanded(!expanded)}
                    className="text-xs text-text-muted hover:text-text-secondary transition-colors mb-3"
                  >
                    {expanded
                      ? t('hideFindings')
                      : t('showFindings', { count: report.findings.length })}
                  </button>

                  <AnimatePresence>
                    {expanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="space-y-2 overflow-hidden"
                      >
                        {report.findings.map((f) => (
                          <div
                            key={f.id}
                            className={`rounded-lg border p-3 ${SEVERITY_COLORS[f.severity] ?? SEVERITY_COLORS.info}`}
                          >
                            <div className="flex items-start justify-between gap-2">
                              <p className="text-xs font-semibold">{f.title}</p>
                              <span className="text-[10px] uppercase font-bold shrink-0">
                                {f.severity}
                              </span>
                            </div>
                            <p className="text-[11px] opacity-80 mt-1">{f.description}</p>
                            {f.location && (
                              <p className="text-[10px] opacity-60 mt-1 font-mono">{f.location}</p>
                            )}
                          </div>
                        ))}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}

              {/* CTA */}
              <div className="px-5 py-4 border-t border-border bg-surface-2/20 text-center">
                <p className="text-xs text-text-muted mb-3">{t('ctaText')}</p>
                <div className="flex flex-wrap gap-2 justify-center">
                  <code className="text-xs bg-surface-2 border border-border rounded-lg px-3 py-2 text-panguard-green font-mono select-all">
                    curl -fsSL https://get.panguard.ai | bash
                  </code>
                  <Link
                    href="/docs/getting-started"
                    className="inline-flex items-center gap-1 text-xs text-panguard-green hover:underline"
                  >
                    {t('learnMore')} <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Trust note */}
        <p className="text-center text-[11px] text-text-muted mt-4">{t('trustNote')}</p>
      </div>
    </section>
  );
}
