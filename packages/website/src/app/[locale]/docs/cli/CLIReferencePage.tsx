'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ChevronDown, ChevronRight } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import { CATEGORIES, type Command } from './cli-data';

/* ──────────────────────────  Sub-components  ─────────────────── */

function MaturityBadge({ maturity, label }: { maturity: 'GA' | 'Beta' | 'Deprecated'; label: string }) {
  if (maturity === 'Deprecated') {
    return (
      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-red-900/30 text-red-400">
        Deprecated
      </span>
    );
  }
  if (maturity === 'Beta') {
    return (
      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-yellow-900/30 text-yellow-400">
        {label}
      </span>
    );
  }
  return (
    <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-green-900/30 text-green-400">
      {label}
    </span>
  );
}

function TierBadge({ tier }: { tier: 'Free' | 'Pro' | 'Enterprise' }) {
  const styles: Record<string, string> = {
    Free: 'bg-surface-2 text-text-muted',
    Pro: 'bg-brand-sage/15 text-brand-sage',
    Enterprise: 'bg-status-info/15 text-status-info',
  };
  return (
    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-full ${styles[tier]}`}>
      {tier}
    </span>
  );
}

function TerminalBlock({ code }: { code: string }) {
  return (
    <div className="bg-[#111] border border-border rounded-xl p-4 font-mono text-sm overflow-x-auto">
      <span className="text-panguard-green">$</span> <span className="text-gray-300">{code}</span>
    </div>
  );
}

function CommandCard({ cmd, t }: { cmd: Command; t: (key: string) => string }) {
  const [expanded, setExpanded] = useState(false);
  const hasFlags = cmd.flags && cmd.flags.length > 0;

  return (
    <div className="bg-surface-1 border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-surface-2/50 transition-colors"
      >
        <span className="text-text-muted shrink-0">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </span>
        <code className="text-text-primary font-mono text-sm font-semibold">{cmd.command}</code>
        <span className="flex items-center gap-2 ml-auto shrink-0">
          <MaturityBadge
            maturity={cmd.maturity}
            label={cmd.maturity === 'Beta' ? t('cli.beta') : cmd.maturity === 'Deprecated' ? 'Deprecated' : t('cli.ga')}
          />
          <TierBadge tier={cmd.tier} />
        </span>
      </button>

      {expanded && (
        <div className="px-5 pb-5 pt-0 border-t border-border/60 space-y-4">
          <p className="text-sm text-text-secondary leading-relaxed pt-4">{t(cmd.descKey)}</p>

          {hasFlags && (
            <div>
              <h4 className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">
                {t('cli.options')}
              </h4>
              <div className="bg-[#0c0d0c] border border-border/60 rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <tbody>
                    {cmd.flags!.map((flag) => (
                      <tr key={flag.name} className="border-b border-border/30 last:border-b-0">
                        <td className="px-4 py-2.5 font-mono text-brand-sage whitespace-nowrap align-top">
                          {flag.name}
                        </td>
                        <td className="px-4 py-2.5 text-text-secondary">
                          {t(flag.descKey)}
                          {flag.default && (
                            <span className="text-text-muted ml-1">(default: {flag.default})</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div>
            <h4 className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-2">
              {t('cli.example')}
            </h4>
            <TerminalBlock code={cmd.example} />
          </div>
        </div>
      )}
    </div>
  );
}

function SidebarNav({
  activeCategory,
  onSelect,
  t,
}: {
  activeCategory: string;
  onSelect: (id: string) => void;
  t: (key: string) => string;
}) {
  return (
    <nav className="hidden lg:block sticky top-24 self-start w-48 shrink-0">
      <p className="text-xs uppercase tracking-wider text-text-muted font-semibold mb-3">
        {t('cli.categories')}
      </p>
      <ul className="space-y-1">
        {CATEGORIES.map((cat) => (
          <li key={cat.id}>
            <button
              onClick={() => onSelect(cat.id)}
              className={`block w-full text-left text-sm px-3 py-1.5 rounded-lg transition-colors ${
                activeCategory === cat.id
                  ? 'text-brand-sage bg-brand-sage/10'
                  : 'text-text-muted hover:text-text-secondary'
              }`}
            >
              {t(`cli.categories.${cat.id}.title`)}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/* ══════════════════════════  Page  ═══════════════════════════ */

export default function CLIReferencePage() {
  const t = useTranslations('docs');
  const [activeCategory, setActiveCategory] = useState(CATEGORIES[0].id);

  const handleCategorySelect = (id: string) => {
    setActiveCategory(id);
    const el = document.getElementById(`category-${id}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <>
      {/* Hero */}
      <SectionWrapper spacing="spacious">
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <Link
              href="/docs"
              className="text-sm text-text-muted hover:text-brand-sage transition-colors"
            >
              {t('cli.backToDocs')}
            </Link>
            <h1 className="text-[clamp(32px,4vw,48px)] font-bold text-text-primary mt-4 leading-[1.1]">
              {t('cli.title')}
            </h1>
            <p className="text-text-secondary mt-4 text-lg leading-relaxed">{t('cli.subtitle')}</p>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Quick install reminder */}
      <SectionWrapper dark spacing="tight">
        <div className="max-w-3xl mx-auto">
          <FadeInUp>
            <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-6">
              <p className="text-sm text-text-secondary shrink-0">{t('cli.installTitle')}</p>
              <div className="bg-[#111] border border-border rounded-xl px-4 py-2.5 font-mono text-sm flex-1 overflow-x-auto">
                <span className="text-panguard-green">$</span>{' '}
                <span className="text-gray-300">curl -fsSL https://get.panguard.ai | bash</span>
              </div>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* Command reference body */}
      <SectionWrapper>
        <div className="flex gap-10 max-w-5xl mx-auto">
          <SidebarNav activeCategory={activeCategory} onSelect={handleCategorySelect} t={t} />

          <div className="flex-1 min-w-0 space-y-12">
            {CATEGORIES.map((category, catIdx) => (
              <FadeInUp key={category.id} delay={catIdx * 0.05}>
                <section id={`category-${category.id}`}>
                  <div className="mb-4">
                    <h2 className="text-xl font-bold text-text-primary">
                      {t(`cli.categories.${category.id}.title`)}
                    </h2>
                    <p className="text-sm text-text-secondary mt-1">
                      {t(`cli.categories.${category.id}.desc`)}
                    </p>
                  </div>
                  <div className="space-y-3">
                    {category.commands.map((cmd) => (
                      <CommandCard key={cmd.command} cmd={cmd} t={t} />
                    ))}
                  </div>
                </section>
              </FadeInUp>
            ))}
          </div>
        </div>
      </SectionWrapper>

      {/* CTA */}
      <SectionWrapper dark spacing="tight" fadeBorder>
        <FadeInUp>
          <div className="text-center">
            <h3 className="text-xl font-bold text-text-primary mb-3">{t('cli.needHelp')}</h3>
            <p className="text-text-secondary text-sm mb-6 max-w-md mx-auto leading-relaxed">
              {t('cli.needHelpDesc')}
            </p>
            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link
                href="/contact"
                className="bg-brand-sage text-surface-0 rounded-full px-6 py-2.5 text-sm font-medium hover:bg-brand-sage-light transition-colors"
              >
                {t('cli.contactSupport')}
              </Link>
              <Link
                href="/docs/getting-started"
                className="border border-border text-text-secondary rounded-full px-6 py-2.5 text-sm font-medium hover:text-text-primary hover:border-text-muted transition-colors"
              >
                {t('cli.gettingStarted')}
              </Link>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
