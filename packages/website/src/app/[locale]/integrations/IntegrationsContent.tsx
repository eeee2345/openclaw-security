'use client';

import { useState, useMemo } from 'react';
import { useTranslations } from 'next-intl';
import { Link } from '@/navigation';
import { ArrowRight, Search } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import {
  IntegrationIcon,
  NetworkIcon,
  TerminalIcon,
  CheckIcon,
  HistoryIcon,
} from '@/components/ui/BrandIcons';

/* ────────────────────────────  Types  ──────────────────────────── */

type Category = 'All' | 'Communication' | 'SIEM & Monitoring' | 'Cloud' | 'DevOps' | 'Ticketing';

type Status = 'Available' | 'Coming Soon';

interface Integration {
  name: string;
  category: Exclude<Category, 'All'>;
  description: string;
  status: Status;
}

/* ────────────────────────────  Data  ───────────────────────────── */

const categories: Category[] = [
  'All',
  'Communication',
  'SIEM & Monitoring',
  'Cloud',
  'DevOps',
  'Ticketing',
];

const integrations: Integration[] = [
  {
    name: 'Slack',
    category: 'Communication',
    description:
      'Real-time alerts, threat notifications, and AI copilot queries in Slack channels.',
    status: 'Available',
  },
  {
    name: 'Microsoft Teams',
    category: 'Communication',
    description: 'Security alerts and Panguard Chat integration for Teams.',
    status: 'Available',
  },
  {
    name: 'LINE',
    category: 'Communication',
    description: 'Alert notifications via LINE messaging for Asia-Pacific teams.',
    status: 'Available',
  },
  {
    name: 'Telegram',
    category: 'Communication',
    description: 'Bot-powered alerts with rich formatting and threat details.',
    status: 'Available',
  },
  {
    name: 'Splunk',
    category: 'SIEM & Monitoring',
    description: 'Forward security events and detection logs to Splunk for centralized analysis.',
    status: 'Available',
  },
  {
    name: 'Elastic (ELK)',
    category: 'SIEM & Monitoring',
    description: 'Ship logs to Elasticsearch for custom dashboards and correlation.',
    status: 'Available',
  },
  {
    name: 'Datadog',
    category: 'SIEM & Monitoring',
    description: 'Security metrics and alerts integrated with Datadog monitoring.',
    status: 'Coming Soon',
  },
  {
    name: 'PagerDuty',
    category: 'DevOps',
    description: 'Trigger incidents from critical security events with automatic escalation.',
    status: 'Available',
  },
  {
    name: 'Jira',
    category: 'Ticketing',
    description: 'Auto-create security tickets from detected threats with full context.',
    status: 'Available',
  },
  {
    name: 'AWS',
    category: 'Cloud',
    description: 'Native integration with AWS CloudTrail, GuardDuty, and Security Hub.',
    status: 'Available',
  },
  {
    name: 'Google Cloud',
    category: 'Cloud',
    description: 'Integration with GCP Security Command Center and Cloud Logging.',
    status: 'Coming Soon',
  },
  {
    name: 'Docker',
    category: 'DevOps',
    description: 'Container security scanning and runtime protection for Docker environments.',
    status: 'Available',
  },
];

/* ────────────────────────────  Helpers  ────────────────────────── */

function StatusBadge({ status, label }: { status: Status; label: string }) {
  const isAvailable = status === 'Available';
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ${
        isAvailable ? 'bg-brand-sage/10 text-brand-sage' : 'bg-amber-500/10 text-amber-400'
      }`}
    >
      {isAvailable ? (
        <CheckIcon size={12} className="text-brand-sage" />
      ) : (
        <HistoryIcon size={12} className="text-amber-400" />
      )}
      {label}
    </span>
  );
}

function CategoryBadge({ category }: { category: string }) {
  return (
    <span className="text-[10px] uppercase tracking-wider font-semibold px-2.5 py-1 rounded-full border border-border text-text-tertiary">
      {category}
    </span>
  );
}

/* ═══════════════════════  Component  ═══════════════════════════ */

export default function IntegrationsContent() {
  const t = useTranslations('integrations');

  const [activeCategory, setActiveCategory] = useState<Category>('All');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = useMemo(() => {
    return integrations.filter((item) => {
      const matchesCategory = activeCategory === 'All' || item.category === activeCategory;
      const matchesSearch =
        searchQuery.trim() === '' ||
        item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.category.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [activeCategory, searchQuery]);

  const apiFeatures = t.raw('developerApi.features') as string[];

  return (
    <>
      {/* -- Hero -- */}
      <SectionWrapper spacing="spacious">
        <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />
      </SectionWrapper>

      {/* -- Search + Filter + Grid -- */}
      <SectionWrapper dark>
        {/* Search */}
        <FadeInUp>
          <div className="max-w-md mx-auto mb-10">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
              <input
                type="text"
                placeholder={t('searchPlaceholder')}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-surface-0 border border-border rounded-full pl-11 pr-5 py-3 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-brand-sage/60 transition-colors"
              />
            </div>
          </div>
        </FadeInUp>

        {/* Category Tabs */}
        <FadeInUp delay={0.05}>
          <div className="flex flex-wrap justify-center gap-2 mb-12">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`text-xs font-semibold uppercase tracking-wider px-4 py-2 rounded-full border transition-all duration-200 ${
                  activeCategory === cat
                    ? 'bg-brand-sage/10 border-brand-sage/40 text-brand-sage'
                    : 'border-border text-text-muted hover:border-brand-sage/30 hover:text-text-secondary'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </FadeInUp>

        {/* Integration Grid */}
        {filtered.length > 0 ? (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {filtered.map((item, i) => (
              <FadeInUp key={item.name} delay={i * 0.04}>
                <div className="bg-surface-1 border border-border rounded-2xl p-6 hover:border-brand-sage/40 transition-all card-glow h-full flex flex-col">
                  {/* Header */}
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <h3 className="text-lg font-semibold text-text-primary">{item.name}</h3>
                    <StatusBadge
                      status={item.status}
                      label={item.status === 'Available' ? t('available') : t('comingSoon')}
                    />
                  </div>

                  {/* Category */}
                  <div className="mb-4">
                    <CategoryBadge category={item.category} />
                  </div>

                  {/* Description */}
                  <p className="text-sm text-text-secondary leading-relaxed flex-1">
                    {item.description}
                  </p>
                </div>
              </FadeInUp>
            ))}
          </div>
        ) : (
          <FadeInUp>
            <div className="text-center py-16">
              <IntegrationIcon size={40} className="text-text-muted mx-auto mb-4" />
              <p className="text-text-secondary">No integrations found matching your search.</p>
              <button
                onClick={() => {
                  setSearchQuery('');
                  setActiveCategory('All');
                }}
                className="text-brand-sage text-sm mt-3 hover:underline"
              >
                Clear filters
              </button>
            </div>
          </FadeInUp>
        )}
      </SectionWrapper>

      {/* -- API Section -- */}
      <SectionWrapper>
        <div className="grid md:grid-cols-2 gap-12 items-center">
          <FadeInUp>
            <div>
              <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
                {t('developerApi.overline')}
              </p>
              <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('developerApi.title')}
              </h2>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('developerApi.desc')}</p>
              <ul className="mt-6 space-y-3">
                {apiFeatures.map((feature: string) => (
                  <li
                    key={feature}
                    className="flex items-start gap-2.5 text-sm text-text-secondary"
                  >
                    <CheckIcon className="w-4 h-4 text-brand-sage mt-0.5 shrink-0" />
                    {feature}
                  </li>
                ))}
              </ul>
              <Link
                href="/docs"
                className="inline-flex items-center gap-2 mt-8 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                View API Documentation <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </FadeInUp>
          <FadeInUp delay={0.1}>
            <div className="bg-surface-1 border border-border rounded-2xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <TerminalIcon size={16} className="text-brand-sage" />
                <span className="text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Example Request
                </span>
              </div>
              <pre className="text-sm text-text-secondary font-mono leading-relaxed overflow-x-auto">
                <code>{`curl -X GET \\
  https://api.panguard.ai/v1/threats \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json"

{
  "data": [
    {
      "id": "thr_9x8kL2",
      "severity": "critical",
      "type": "brute_force",
      "endpoint": "api-gateway-01",
      "detected_at": "2025-01-15T08:32:00Z"
    }
  ],
  "meta": { "total": 47, "page": 1 }
}`}</code>
              </pre>
            </div>
          </FadeInUp>
        </div>
      </SectionWrapper>

      {/* -- Request Integration CTA -- */}
      <SectionWrapper dark>
        <FadeInUp>
          <div className="text-center max-w-2xl mx-auto">
            <NetworkIcon size={40} className="text-brand-sage mx-auto mb-6" />
            <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
              {t('dontSeeYourTool')}
            </h2>
            <p className="text-text-secondary mt-4 leading-relaxed">{t('dontSeeDesc')}</p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
              <Link
                href="/contact"
                className="inline-flex items-center gap-2 bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3.5 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
              >
                {t('requestIntegration')} <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/docs"
                className="border border-border text-text-secondary hover:text-text-primary hover:border-brand-sage font-semibold rounded-full px-8 py-3.5 transition-all duration-200"
              >
                {t('buildYourOwn')}
              </Link>
            </div>
          </div>
        </FadeInUp>
      </SectionWrapper>
    </>
  );
}
