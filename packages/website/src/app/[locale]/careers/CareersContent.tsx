'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import {
  GlobalIcon,
  DeployIcon,
  ShieldIcon,
  AnalyticsIcon,
  CheckIcon,
} from '@/components/ui/BrandIcons';
import { departments, jobListings, type JobListing } from '@/data/job-listings';

/* ─── Culture Values ─── */

const cultureIcons = [GlobalIcon, DeployIcon, ShieldIcon, AnalyticsIcon];
const cultureKeys = ['item1', 'item2', 'item3', 'item4'] as const;

/* ─── Benefits Keys ─── */

const benefitKeys = [
  'item1',
  'item2',
  'item3',
  'item4',
  'item5',
  'item6',
  'item7',
  'item8',
] as const;

/* ─── Job Card ─── */

function JobCard({ job }: { job: JobListing }) {
  return (
    <Link
      href={`/careers/${job.id}`}
      className="bg-surface-1 border border-border rounded-xl p-5 hover:border-brand-sage/40 transition-all flex items-center justify-between group"
    >
      <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
        <h3 className="text-sm font-semibold text-text-primary">{job.title}</h3>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full bg-brand-sage/10 text-brand-sage">
            {job.department}
          </span>
          <span className="text-xs text-text-tertiary">{job.location}</span>
          <span className="text-xs text-text-muted">{job.type}</span>
        </div>
      </div>
      <ArrowRight className="w-4 h-4 text-text-muted group-hover:text-brand-sage transition-colors shrink-0 ml-4" />
    </Link>
  );
}

/* ════════════════════════  Main Component  ═══════════════════════ */

export default function CareersContent() {
  const t = useTranslations('careers');

  const [activeDept, setActiveDept] = useState('All');

  const filteredJobs =
    activeDept === 'All' ? jobListings : jobListings.filter((j) => j.department === activeDept);

  return (
    <>
      {/* ── Hero ── */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} serif />
      </SectionWrapper>

      {/* ── Mission Statement ── */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="max-w-2xl mx-auto text-center">
            <p className="text-lg sm:text-xl text-text-secondary leading-relaxed">
              {t('missionStatement')}
            </p>
          </div>
        </FadeInUp>
      </SectionWrapper>

      {/* ── Culture Values ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('culture.overline')}
          title={t('culture.title')}
          subtitle={t('culture.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-6 mt-14">
          {cultureKeys.map((key, i) => {
            const Icon = cultureIcons[i];
            return (
              <FadeInUp key={key} delay={i * 0.08}>
                <div className="bg-surface-1 border border-border rounded-2xl p-6 card-glow h-full">
                  <Icon className="w-6 h-6 text-brand-sage mb-4" />
                  <p className="text-sm font-bold text-text-primary mb-2">
                    {t(`culture.${key}.title`)}
                  </p>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {t(`culture.${key}.desc`)}
                  </p>
                </div>
              </FadeInUp>
            );
          })}
        </div>
      </SectionWrapper>

      {/* ── Benefits ── */}
      <SectionWrapper dark>
        <SectionTitle
          overline={t('benefits.overline')}
          title={t('benefits.title')}
          subtitle={t('benefits.subtitle')}
        />
        <div className="grid sm:grid-cols-2 gap-x-12 gap-y-4 mt-14 max-w-2xl mx-auto">
          {benefitKeys.map((key, i) => (
            <FadeInUp key={key} delay={i * 0.04}>
              <div className="flex items-center gap-3">
                <CheckIcon className="w-4 h-4 text-brand-sage shrink-0" />
                <span className="text-sm text-text-secondary">{t(`benefits.${key}`)}</span>
              </div>
            </FadeInUp>
          ))}
        </div>
      </SectionWrapper>

      {/* ── Open Positions ── */}
      <SectionWrapper>
        <SectionTitle
          overline={t('positions.overline')}
          title={t('positions.title')}
          subtitle={`${jobListings.length} roles open across ${departments.length - 1} departments. All positions are remote-friendly.`}
        />

        {/* Department filter tabs */}
        <FadeInUp>
          <div className="flex flex-wrap justify-center gap-2 mt-10">
            {departments.map((dept) => (
              <button
                key={dept}
                onClick={() => setActiveDept(dept)}
                className={`text-xs font-semibold px-4 py-2 rounded-full transition-all duration-200 ${
                  activeDept === dept
                    ? 'bg-brand-sage text-surface-0'
                    : 'bg-surface-1 border border-border text-text-secondary hover:border-brand-sage/40 hover:text-text-primary'
                }`}
              >
                {dept}
              </button>
            ))}
          </div>
        </FadeInUp>

        {/* Job listings */}
        <div className="mt-8 space-y-3 max-w-3xl mx-auto">
          {filteredJobs.map((job, i) => (
            <FadeInUp key={job.id} delay={i * 0.05}>
              <JobCard job={job} />
            </FadeInUp>
          ))}
          {filteredJobs.length === 0 && (
            <FadeInUp>
              <p className="text-center text-text-tertiary text-sm py-8">
                {t('positions.noPositions')}
              </p>
            </FadeInUp>
          )}
        </div>
      </SectionWrapper>

      {/* ── Apply CTA ── */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="text-center max-w-2xl mx-auto">
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('spontaneous.title')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">
              {t('spontaneous.desc')}{' '}
              <a
                href={`mailto:${t('spontaneous.email')}`}
                className="text-brand-sage hover:underline"
              >
                {t('spontaneous.email')}
              </a>
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
              <Link
                href="/contact"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('spontaneous.cta1')} <ArrowRight className="w-4 h-4" />
              </Link>
              <a
                href={`mailto:${t('spontaneous.email')}`}
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3 transition-all duration-200"
              >
                {t('spontaneous.cta2')}
              </a>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
