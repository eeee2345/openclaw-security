'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight, ExternalLink } from 'lucide-react';
import {
  ShieldIcon,
  NetworkIcon,
  TerminalIcon,
  CheckIcon,
} from '@/components/ui/BrandIcons';

/* ─── Why Icons ─── */
const whyIcons = [ShieldIcon, NetworkIcon, TerminalIcon];
const whyKeys = ['reason1', 'reason2', 'reason3'] as const;

/* ─── Roadmap Status Colors ─── */
const roadmapSections = [
  { key: 'completed' as const, badge: 'bg-brand-sage/10 text-brand-sage' },
  { key: 'inProgress' as const, badge: 'bg-[#f59e0b]/10 text-[#f59e0b]' },
  { key: 'planned' as const, badge: 'bg-surface-3 text-text-tertiary' },
];

export default function OpenSourceContent() {
  const t = useTranslations('openSource');

  return (
    <>
      {/* ── Hero ── */}
      <section className="relative min-h-[60vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative text-center w-full">
          <FadeInUp>
            <div className="relative w-20 h-20 mx-auto mb-4 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-brand-sage/20 animate-[spin_12s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-brand-sage/10 animate-[spin_8s_linear_infinite_reverse]" />
              <TerminalIcon className="w-10 h-10 text-brand-sage relative" />
            </div>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-4">
              {t('overline')}
            </p>
            <h1 className="text-[clamp(36px,4.5vw,56px)] font-extrabold leading-[1.08] tracking-tight text-text-primary max-w-3xl mx-auto">
              {t('title')} <span className="text-brand-sage">{t('titleHighlight')}</span>
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mx-auto mt-6 leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* ── Why Open Source ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('why.overline')}
          title={t('why.title')}
          subtitle={t('why.subtitle')}
        />
        <div className="grid sm:grid-cols-3 gap-4 mt-14">
          {whyKeys.map((key, i) => {
            const Icon = whyIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-1 rounded-xl border border-border p-6 h-full card-glow">
                  <Icon className="w-6 h-6 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary mb-2">{t(`why.${key}.title`)}</p>
                  <p className="text-sm text-text-secondary leading-relaxed">{t(`why.${key}.desc`)}</p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── Repositories ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('repos.overline')}
          title={t('repos.title')}
          subtitle={t('repos.subtitle')}
        />
        <div className="grid sm:grid-cols-3 gap-4 mt-14">
          {(t.raw('repos.items') as Array<{ name: string; desc: string; lang: string; stars: string }>).map((repo, i) => (
            <FadeInUp key={repo.name} delay={i * 0.08}>
              <div className="bg-surface-2 rounded-xl border border-border p-6 h-full flex flex-col">
                <p className="font-mono text-sm font-bold text-text-primary mb-2">{repo.name}</p>
                <p className="text-sm text-text-secondary leading-relaxed flex-1">{repo.desc}</p>
                <div className="flex items-center gap-2 mt-4 pt-4 border-t border-border">
                  <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full bg-brand-sage/10 text-brand-sage">
                    {repo.lang}
                  </span>
                  <span className="text-[10px] text-text-tertiary">{repo.stars}</span>
                </div>
                <a
                  href={`https://github.com/panguard-ai/${repo.name}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-sage mt-3 hover:gap-2.5 transition-all duration-200"
                >
                  View on GitHub <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── How to Contribute ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('contribute.overline')}
          title={t('contribute.title')}
          subtitle={t('contribute.subtitle')}
        />
        <div className="max-w-2xl mx-auto mt-14 space-y-6">
          {(t.raw('contribute.items') as Array<{ title: string; desc: string }>).map((item, i) => (
            <FadeInUp key={item.title} delay={i * 0.06}>
              <div className="flex gap-4">
                <div className="shrink-0">
                  <div className="w-8 h-8 rounded-full bg-brand-sage/10 text-brand-sage flex items-center justify-center text-xs font-bold">
                    {i + 1}
                  </div>
                </div>
                <div>
                  <p className="text-sm font-semibold text-text-primary">{item.title}</p>
                  <p className="text-sm text-text-secondary mt-1">{item.desc}</p>
                </div>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── Roadmap ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('roadmap.overline')}
          title={t('roadmap.title')}
          subtitle={t('roadmap.subtitle')}
        />
        <div className="grid sm:grid-cols-3 gap-4 mt-14">
          {roadmapSections.map((section, i) => (
            <FadeInUp key={section.key} delay={i * 0.08}>
              <div className="bg-surface-2 rounded-xl border border-border p-6 h-full">
                <span className={`${section.badge} text-[10px] font-semibold uppercase tracking-wider px-2.5 py-1 rounded-full`}>
                  {t(`roadmap.${section.key}.title`)}
                </span>
                <ul className="mt-4 space-y-2.5">
                  {(t.raw(`roadmap.${section.key}.items`) as string[]).map((item, j) => (
                    <li key={j} className="flex items-start gap-2 text-sm text-text-secondary">
                      <CheckIcon className="w-3.5 h-3.5 text-brand-sage mt-0.5 shrink-0" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── CTA ── */}
      <SectionWrapper>
        <div className="text-center max-w-2xl mx-auto">
          <FadeInUp>
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-3 mb-4">{t('cta.desc')}</p>
            <code className="block text-sm bg-black/50 text-brand-sage px-6 py-3 rounded-lg mb-8 inline-block font-mono">
              $ git clone https://github.com/panguard-ai/panguard-ai.git
            </code>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3">
              <a
                href="https://github.com/panguard-ai/panguard-ai"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.primary')} <ExternalLink className="w-4 h-4" />
              </a>
              <Link
                href="/docs"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.secondary')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
