"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Copy, Check, ArrowRight, Loader2 } from "lucide-react";
import FadeInUp from "../FadeInUp";
import SectionWrapper from "../ui/SectionWrapper";
import { AlertIcon, CheckIcon as BrandCheck, NetworkIcon, LockIcon } from "@/components/ui/BrandIcons";

const installCmd = "curl -fsSL https://get.panguard.ai | sh";

interface ScanResult {
  target: string;
  score: number;
  grade: string;
  findings: Array<{
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    detail: string;
  }>;
  openPorts: number[];
  ssl: { valid: boolean; expiresIn: number; protocol: string } | null;
}

const severityColors: Record<string, string> = {
  critical: "text-status-alert",
  high: "text-status-alert",
  medium: "text-status-caution",
  low: "text-text-secondary",
  info: "text-text-tertiary",
};

function gradeColor(grade: string) {
  if (grade === "A" || grade === "A+") return "text-status-safe";
  if (grade === "B") return "text-brand-sage";
  if (grade === "C") return "text-status-caution";
  return "text-status-alert";
}

export default function CallToAction() {
  const t = useTranslations("home.cta");
  const [copied, setCopied] = useState(false);
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  const handleCopy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setScanning(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: domain.trim() }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.error || "Scan failed");
      }
      const data = await res.json();
      setResult(data);
    } catch {
      setError(t("scanError"));
    } finally {
      setScanning(false);
    }
  }

  function resetScan() {
    setResult(null);
    setDomain("");
    setError("");
  }

  return (
    <SectionWrapper>
      <div className="max-w-2xl mx-auto text-center">
        <FadeInUp>
          <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
            {t("title")}
          </h2>
          <p className="text-text-secondary mt-3">
            {t("subtitle")}
          </p>
        </FadeInUp>

        {/* Curl install */}
        <FadeInUp delay={0.1}>
          <p className="text-xs text-text-muted uppercase tracking-wider mt-10 mb-3">
            {t("curlLabel")}
          </p>
          <div className="relative flex items-center gap-3 bg-surface-1 border border-border rounded-xl px-5 py-3.5 font-mono text-sm">
            <span className="text-brand-sage select-none">$</span>
            <code className="text-text-secondary flex-1 select-all truncate text-left">
              {installCmd}
            </code>
            <button
              onClick={handleCopy}
              className="text-text-muted hover:text-text-secondary transition-colors p-1 shrink-0"
              aria-label="Copy install command"
            >
              {copied ? (
                <Check className="w-4 h-4 text-status-safe" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
            {copied && (
              <span className="toast-copied absolute -top-8 left-1/2 -translate-x-1/2 text-xs text-status-safe bg-surface-1 border border-border rounded px-2 py-1">
                {t("copied")}
              </span>
            )}
          </div>
        </FadeInUp>

        {/* Online scan */}
        <FadeInUp delay={0.2}>
          <p className="text-xs text-text-muted uppercase tracking-wider mt-10 mb-3">
            {t("orScanOnline")}
          </p>
          {!result ? (
            <div className="max-w-[600px] mx-auto">
              <form onSubmit={handleScan} className="flex gap-2">
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder={t("scanPlaceholder")}
                  className="flex-1 bg-surface-1 border border-border rounded-xl px-5 py-4 text-base text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage transition-colors"
                  disabled={scanning}
                />
                <button
                  type="submit"
                  disabled={scanning || !domain.trim()}
                  className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-xl px-6 py-4 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed text-base"
                >
                  {scanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      {t("scanning")}
                    </>
                  ) : (
                    <>
                      {t("freeScanButton")} <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>
              <p className="text-xs text-text-muted mt-3">
                {t("privacyNote")}
              </p>
            </div>
          ) : (
            <div className="bg-surface-1 border border-border rounded-xl p-6 text-left mt-2">
              {/* Score + Grade */}
              <div className="flex items-center gap-6 mb-6">
                <div>
                  <p className="text-xs text-text-muted uppercase tracking-wider">{t("score")}</p>
                  <p className="text-3xl font-extrabold text-text-primary">{result.score}/100</p>
                </div>
                <div>
                  <p className="text-xs text-text-muted uppercase tracking-wider">{t("grade")}</p>
                  <p className={`text-3xl font-extrabold ${gradeColor(result.grade)}`}>{result.grade}</p>
                </div>
              </div>

              {/* Open Ports */}
              {result.openPorts.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <NetworkIcon className="w-3.5 h-3.5" />
                    {t("openPorts")}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {result.openPorts.map((port) => (
                      <span key={port} className="text-xs bg-surface-2 border border-border rounded-full px-3 py-1 text-text-secondary font-mono">
                        {port}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* SSL */}
              <div className="mb-4">
                <p className="text-xs text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <LockIcon className="w-3.5 h-3.5" />
                  {t("ssl")}
                </p>
                {result.ssl ? (
                  <p className={`text-sm ${result.ssl.valid ? "text-status-safe" : "text-status-alert"}`}>
                    {result.ssl.valid ? t("sslValid") : t("sslInvalid")}
                    {result.ssl.valid && ` - ${t("sslExpires", { days: result.ssl.expiresIn })}`}
                  </p>
                ) : (
                  <p className="text-sm text-text-muted">{t("noSsl")}</p>
                )}
              </div>

              {/* Findings */}
              {result.findings.length > 0 && (
                <div>
                  <p className="text-xs text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <AlertIcon className="w-3.5 h-3.5" />
                    {t("findings")}
                  </p>
                  <div className="space-y-2">
                    {result.findings.map((f, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        <span className={`text-[10px] uppercase font-bold mt-0.5 shrink-0 ${severityColors[f.severity]}`}>
                          {f.severity}
                        </span>
                        <div>
                          <p className="text-text-primary font-medium">{f.title}</p>
                          <p className="text-text-tertiary text-xs">{f.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {result.findings.length === 0 && (
                <div className="flex items-center gap-2 text-status-safe text-sm">
                  <BrandCheck className="w-4 h-4" />
                  {t("noIssues")}
                </div>
              )}

              <button
                onClick={resetScan}
                className="mt-6 text-sm text-brand-sage hover:text-brand-sage-light transition-colors"
              >
                {t("scanAnother")}
              </button>
            </div>
          )}
          {error && (
            <p className="text-sm text-status-alert mt-3">{error}</p>
          )}
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
