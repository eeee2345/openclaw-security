"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import { motion } from "framer-motion";
import { Copy, Check, ArrowRight, CheckCircle } from "lucide-react";
import { Link } from "@/navigation";

/* ─── Install Command (never translated) ─── */
const installCmd = "curl -fsSL https://get.panguard.ai | sh";

function InstallBar() {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="relative flex items-center gap-3 bg-surface-1/80 backdrop-blur-sm border border-border rounded-xl px-5 py-3.5 font-mono text-sm max-w-md mx-auto">
      <span className="text-brand-sage select-none">$</span>
      <code className="text-text-secondary flex-1 select-all truncate">{installCmd}</code>
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
          Copied!
        </span>
      )}
    </div>
  );
}

/* ═══════════════════════  Hero Component  ═══════════════════════ */

export default function Hero() {
  const t = useTranslations("home.hero");

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* ── Background: pure CSS, no JS animation overhead ── */}

      {/* Grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(139,154,142,1) 1px, transparent 1px), linear-gradient(90deg, rgba(139,154,142,1) 1px, transparent 1px)",
          backgroundSize: "80px 80px",
        }}
      />

      {/* Central glow orb -- CSS animation */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full pointer-events-none hero-orb" />

      {/* Scan line -- CSS animation */}
      <div className="absolute left-0 right-0 pointer-events-none hero-scanline" />

      {/* ── Content ── */}
      <div className="relative z-10 text-center px-6 py-24 max-w-4xl mx-auto">
        {/* Title */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
        >
          <h1 className="text-[clamp(48px,8vw,96px)] font-extrabold leading-[1.05] tracking-tight text-text-primary">
            {t("title")}
          </h1>
        </motion.div>

        {/* Subtitle */}
        <motion.div
          className="mt-6 max-w-xl mx-auto"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed">
            {t("subtitle1")}
          </p>
          <p className="text-xl lg:text-2xl text-text-secondary leading-relaxed mt-1">
            {t("subtitle2")}
          </p>
          <p className="text-base lg:text-lg text-text-tertiary leading-relaxed mt-3 font-mono">
            {t("subtitle3")}
          </p>
        </motion.div>

        {/* Install command */}
        <motion.div
          className="mt-10"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.4 }}
        >
          <InstallBar />
        </motion.div>

        {/* Buttons */}
        <motion.div
          className="flex flex-wrap gap-3 justify-center mt-8"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.4, delay: 0.55 }}
        >
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
          >
            {t("freeScan")} <ArrowRight className="w-4 h-4" />
          </Link>
          <a
            href="https://github.com/eeee2345/openclaw-security"
            target="_blank"
            rel="noopener noreferrer"
            className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
          >
            {t("github")}
          </a>
        </motion.div>

        {/* Social proof badges */}
        <motion.div
          className="flex flex-wrap gap-3 justify-center mt-6"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.4, delay: 0.7 }}
        >
          {(["mit", "tests", "typescript", "taiwan"] as const).map((key) => (
            <span
              key={key}
              className="inline-flex items-center gap-1.5 text-xs text-text-tertiary bg-surface-1/50 border border-border/50 rounded-full px-3 py-1.5"
            >
              <CheckCircle className="w-3 h-3 text-brand-sage" />
              {t(`badges.${key}`)}
            </span>
          ))}
        </motion.div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-surface-0 to-transparent pointer-events-none" />
    </section>
  );
}
