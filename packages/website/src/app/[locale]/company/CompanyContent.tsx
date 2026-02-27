'use client';

import { useTranslations } from 'next-intl';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import {
  ShieldIcon,
  TeamIcon,
  TerminalIcon,
  HistoryIcon,
  EnterpriseIcon,
  ResponseIcon,
} from '@/components/ui/BrandIcons';

/* ─── Values ─── */
const valueIcons = [ResponseIcon, TerminalIcon, HistoryIcon, TeamIcon];
const valueKeys = ['item1', 'item2', 'item3', 'item4'] as const;

/* ─── Open Roles ─── */
const openRoles = [
  {
    title: 'Founder & CEO',
    type: 'Leadership',
    description:
      'Security practitioner and serial entrepreneur to lead the company vision. Build the team, shape the product, and bring enterprise-grade security to the other 400 million businesses.',
  },
  {
    title: 'CTO',
    type: 'Leadership',
    description:
      'Principal-level engineer with deep expertise in AI/ML systems, distributed architectures, and threat detection. Lead the technical vision and open-source strategy.',
  },
  {
    title: 'Head of AI',
    type: 'Engineering',
    description:
      'ML researcher focused on anomaly detection to lead AI research and build the next generation of autonomous threat detection agents.',
  },
  {
    title: 'Head of Product',
    type: 'Product',
    description:
      'Product leader obsessed with reducing friction. Make complex security systems feel simple for developers and small business owners.',
  },
];

export default function CompanyContent() {
  const t = useTranslations('company');

  return (
    <>
      {/* ── Hero / Mission ── */}
      <section className="relative min-h-[60vh] flex items-center px-6 lg:px-[120px] py-24 border-b border-border overflow-hidden">
        <div className="absolute top-1/4 left-1/3 w-[700px] h-[400px] bg-brand-sage/5 rounded-full blur-[200px] pointer-events-none" />
        <div className="max-w-[1200px] mx-auto relative">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.15em] text-brand-sage font-semibold mb-6">
              {t('overline')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.05}>
            <h1 className="text-[clamp(36px,4.5vw,56px)] font-extrabold leading-[1.1] tracking-tight text-text-primary max-w-4xl">
              {t('title')}
            </h1>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <p className="text-xl text-text-secondary max-w-2xl mt-6 leading-relaxed">
              {t('mission')}
            </p>
          </FadeInUp>
        </div>
      </section>

      {/* ── Brand Story ── */}
      <SectionWrapper>
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <FadeInUp>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('name.overline')}
              </p>
              <h2 className="text-[clamp(32px,3.5vw,44px)] font-bold text-text-primary leading-[1.1]">
                {t('name.title')}
              </h2>
              <p className="text-lg text-text-secondary mt-2">{t('name.etymology')}</p>
            </FadeInUp>
            <FadeInUp delay={0.1}>
              <p className="text-text-secondary mt-6 leading-relaxed">{t('name.desc1')}</p>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('name.desc2')}</p>
            </FadeInUp>
          </div>
          <FadeInUp delay={0.15}>
            <div className="bg-surface-1 rounded-xl border border-border p-8 lg:p-10">
              <ShieldIcon className="w-10 h-10 text-brand-sage mb-6" />
              <blockquote className="text-xl font-semibold text-text-primary leading-relaxed italic">
                &ldquo;{t('quote.text')}&rdquo;
              </blockquote>
              <p className="text-sm text-text-tertiary mt-4">{t('quote.attribution')}</p>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* ── Values ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('values.overline')}
          title={t('values.title')}
          subtitle={t('values.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-6 mt-14">
          {valueKeys.map((key, i) => {
            const Icon = valueIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-2 rounded-xl border border-border p-6 h-full">
                  <Icon className="w-6 h-6 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary">{t(`values.${key}.title`)}</p>
                  <p className="text-[11px] uppercase tracking-wider text-brand-sage font-semibold mt-0.5 mb-3">
                    {t(`values.${key}.subtitle`)}
                  </p>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {t(`values.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── We're Hiring ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('team.overline')}
          title={t('team.title')}
          subtitle={t('team.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-6 mt-14">
          {openRoles.map((role, i) => (
            <FadeInUp key={role.title} delay={i * 0.08}>
              <div className="bg-surface-1 rounded-xl border border-border p-6 h-full flex flex-col">
                <p className="text-[11px] uppercase tracking-wider text-brand-sage font-semibold mb-2">
                  {role.type}
                </p>
                <h3 className="text-lg font-bold text-text-primary mb-3">{role.title}</h3>
                <p className="text-sm text-text-secondary leading-relaxed flex-1">
                  {role.description}
                </p>
                <Link
                  href="/careers"
                  className="inline-flex items-center gap-2 text-sm font-semibold text-brand-sage mt-4 hover:gap-3 transition-all duration-200"
                >
                  Learn More <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── Investors & Advisors ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('investors.overline')}
          title={t('investors.title')}
          subtitle={t('investors.subtitle')}
        />
        <FadeInUp>
          <div className="max-w-xl mx-auto mt-10 bg-surface-2 rounded-xl border border-border p-8 text-center">
            <TeamIcon className="w-8 h-8 text-brand-sage mx-auto mb-4" />
            <p className="text-text-secondary text-sm leading-relaxed">{t('investors.desc')}</p>
            <Link
              href="/contact"
              className="inline-flex items-center gap-2 text-sm font-semibold text-brand-sage mt-4 hover:gap-3 transition-all duration-200"
            >
              {t('investors.advisingCta')} <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ── Careers CTA ── */}
      <SectionWrapper>
        <div className="text-center">
          <FadeInUp>
            <EnterpriseIcon className="w-8 h-8 text-brand-sage mx-auto mb-4" />
            <h2 className="text-[clamp(28px,3vw,40px)] font-bold text-text-primary">
              {t('cta.title')}
            </h2>
            <p className="text-text-secondary mt-4 max-w-xl mx-auto leading-relaxed">
              {t('cta.desc')}
            </p>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="flex flex-wrap justify-center gap-3 mt-8">
              <Link
                href="/careers"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('cta.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/contact"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('cta.cta2')}
              </Link>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>
    </>
  );
}
