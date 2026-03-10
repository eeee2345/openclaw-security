'use client';

import { Check, X, Minus } from 'lucide-react';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import { Link } from '@/navigation';

/* ------------------------------------------------------------------ */
/*  Data                                                               */
/* ------------------------------------------------------------------ */

type CellValue = 'yes' | 'no' | 'partial' | string;

interface ComparisonRow {
  readonly feature: string;
  readonly panguard: CellValue;
  readonly manual: CellValue;
  readonly siem: CellValue;
  readonly none: CellValue;
}

const COMPARISON_ROWS: readonly ComparisonRow[] = [
  {
    feature: 'Setup time',
    panguard: '5 minutes (one command)',
    manual: '2\u20134 weeks',
    siem: '1\u20133 months',
    none: 'N/A',
  },
  {
    feature: 'Detection speed',
    panguard: '<50 ms (rules), ~2 s (AI)',
    manual: 'Days to weeks',
    siem: 'Minutes to hours',
    none: 'Never',
  },
  {
    feature: 'AI agent threat detection',
    panguard: 'yes',
    manual: 'no',
    siem: 'no',
    none: 'no',
  },
  {
    feature: 'Prompt injection detection',
    panguard: 'yes',
    manual: 'no',
    siem: 'no',
    none: 'no',
  },
  {
    feature: 'Cost (10 endpoints / yr)',
    panguard: '$348/yr (Pro)',
    manual: '$20K\u2013$50K / engagement',
    siem: '$15K\u2013$60K/yr',
    none: '$0 (until breach)',
  },
  {
    feature: 'Detection rules',
    panguard: '9,000+ (Sigma + YARA + ATR)',
    manual: 'Depends on auditor',
    siem: 'Varies by vendor',
    none: '0',
  },
  {
    feature: 'Automated response',
    panguard: '6 response actions',
    manual: 'Report only',
    siem: 'Varies',
    none: 'None',
  },
  {
    feature: 'Compliance reports',
    panguard: 'Auto-generated (ISO / SOC 2)',
    manual: 'Manual (consultant)',
    siem: 'Manual or basic',
    none: 'None',
  },
  {
    feature: 'AI-powered analysis',
    panguard: '3-layer funnel',
    manual: 'Human only',
    siem: 'Basic ML',
    none: 'None',
  },
  {
    feature: 'Honeypot intelligence',
    panguard: 'yes',
    manual: 'no',
    siem: 'no',
    none: 'no',
  },
  {
    feature: 'Notification channels',
    panguard: '5 (Telegram / Slack / LINE / Email / Webhook)',
    manual: 'Email report',
    siem: 'Email / SIEM console',
    none: 'None',
  },
  {
    feature: 'Open-source rules',
    panguard: 'yes',
    manual: 'no',
    siem: 'no',
    none: 'N/A',
  },
] as const;

interface ComparisonCard {
  readonly title: string;
  readonly bullets: readonly string[];
}

const COMPARISON_CARDS: readonly ComparisonCard[] = [
  {
    title: 'Panguard vs Manual Security Audit',
    bullets: [
      'Manual audits are point-in-time snapshots. Panguard monitors 24/7.',
      'Cost: $20K\u2013$50K per engagement vs $0 (open source).',
      'Output: Static PDF report vs live dashboard + auto-remediation.',
      'Best for: Annual compliance checks (manual) vs continuous protection (Panguard).',
    ],
  },
  {
    title: 'Panguard vs Traditional SIEM',
    bullets: [
      'SIEM requires a dedicated security team to manage.',
      'Setup: Months of tuning vs one-command install.',
      'AI agents: SIEM has no AI agent threat-model awareness.',
      'Best for: Enterprise SOC teams (SIEM) vs lean engineering teams (Panguard).',
    ],
  },
  {
    title: 'Panguard vs No Protection',
    bullets: [
      'Average cost of a data breach: $4.88 M (IBM 2024).',
      'Mean time to detect without tools: 204 days (IBM 2024).',
      'Panguard is 100% open source under the MIT license.',
      'The question isn\'t whether you can afford Panguard \u2014 it\'s whether you can afford not to use it.',
    ],
  },
] as const;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function CellContent({ value }: { value: CellValue }) {
  if (value === 'yes') {
    return <Check className="w-5 h-5 text-brand-sage mx-auto" aria-label="Yes" />;
  }
  if (value === 'no') {
    return <X className="w-5 h-5 text-text-muted mx-auto" aria-label="No" />;
  }
  if (value === 'partial') {
    return <Minus className="w-5 h-5 text-text-tertiary mx-auto" aria-label="Partial" />;
  }
  return <span>{value}</span>;
}

/* ------------------------------------------------------------------ */
/*  Sections                                                           */
/* ------------------------------------------------------------------ */

function HeroSection() {
  return (
    <section className="pt-24 pb-4 px-6 text-center">
      <FadeInUp>
        <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
          Compare
        </p>
        <h1 className="text-[clamp(30px,5vw,64px)] font-bold text-text-primary leading-[1.08] max-w-3xl mx-auto">
          How Panguard Compares
        </h1>
        <p className="text-text-secondary mt-4 text-lg max-w-xl mx-auto leading-relaxed">
          AI-era endpoint security vs traditional approaches. See why teams choose Panguard.
        </p>
      </FadeInUp>
    </section>
  );
}

function ComparisonTable() {
  const columns = ['Panguard', 'Manual Audit', 'Traditional SIEM', 'No Protection'] as const;
  const colKeys = ['panguard', 'manual', 'siem', 'none'] as const;

  return (
    <SectionWrapper dark>
      <SectionTitle
        overline="Feature-by-feature"
        title="Side-by-Side Comparison"
        subtitle="How Panguard stacks up against the most common alternatives."
      />

      <FadeInUp>
        {/* Desktop table */}
        <div className="mt-10 overflow-x-auto hidden md:block">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr>
                <th className="text-left py-3 px-4 text-text-tertiary font-medium border-b border-border w-[200px]">
                  Feature
                </th>
                {columns.map((col, i) => (
                  <th
                    key={col}
                    className={`py-3 px-4 font-semibold border-b text-center ${
                      i === 0
                        ? 'text-brand-sage border-brand-sage/40'
                        : 'text-text-secondary border-border'
                    }`}
                  >
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARISON_ROWS.map((row) => (
                <tr key={row.feature} className="border-b border-border/50 hover:bg-surface-2/30 transition-colors">
                  <td className="py-3 px-4 text-text-primary font-medium">{row.feature}</td>
                  {colKeys.map((key, i) => (
                    <td
                      key={key}
                      className={`py-3 px-4 text-center text-text-secondary ${
                        i === 0 ? 'bg-brand-sage/5' : ''
                      }`}
                    >
                      <CellContent value={row[key]} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Mobile cards */}
        <div className="mt-10 space-y-4 md:hidden">
          {COMPARISON_ROWS.map((row) => (
            <div key={row.feature} className="bg-surface-2 rounded-xl border border-border p-4">
              <p className="text-text-primary font-semibold text-sm mb-3">{row.feature}</p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {colKeys.map((key, i) => (
                  <div key={key} className={`flex flex-col gap-1 ${i === 0 ? 'text-brand-sage' : 'text-text-secondary'}`}>
                    <span className="text-text-tertiary font-medium">{columns[i]}</span>
                    <CellContent value={row[key]} />
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </FadeInUp>
    </SectionWrapper>
  );
}

function ComparisonCards() {
  return (
    <SectionWrapper>
      <SectionTitle
        overline="Deep dive"
        title="Detailed Comparisons"
        subtitle="Explore how Panguard differs from each alternative in depth."
      />

      <div className="mt-10 grid grid-cols-1 lg:grid-cols-3 gap-6">
        {COMPARISON_CARDS.map((card, idx) => (
          <FadeInUp key={card.title} delay={idx * 0.1}>
            <div className="bg-surface-1 rounded-xl border border-border p-6 h-full flex flex-col">
              <h3 className="text-lg font-bold text-text-primary mb-4">{card.title}</h3>
              <ul className="space-y-3 flex-1">
                {card.bullets.map((bullet) => (
                  <li key={bullet} className="flex items-start gap-2 text-sm text-text-secondary leading-relaxed">
                    <span className="mt-1.5 block w-1.5 h-1.5 rounded-full bg-brand-sage shrink-0" />
                    {bullet}
                  </li>
                ))}
              </ul>
            </div>
          </FadeInUp>
        ))}
      </div>
    </SectionWrapper>
  );
}

function CTASection() {
  return (
    <SectionWrapper dark>
      <FadeInUp>
        <div className="text-center max-w-2xl mx-auto">
          <h2 className="text-[clamp(20px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
            Start protecting your infrastructure today
          </h2>
          <p className="text-text-secondary mt-4 leading-relaxed">
            Deploy Panguard in under five minutes. 100% open source, MIT licensed.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
            <Link
              href="/docs/getting-started"
              className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
            >
              Get Started Free
            </Link>
            <Link
              href="/pricing"
              className="border border-border text-text-secondary font-semibold rounded-full px-8 py-3 hover:border-brand-sage hover:text-text-primary transition-all duration-200"
            >
              View Pricing
            </Link>
          </div>
        </div>
      </FadeInUp>
    </SectionWrapper>
  );
}

/* ------------------------------------------------------------------ */
/*  Root                                                               */
/* ------------------------------------------------------------------ */

export default function CompareContent() {
  return (
    <>
      <HeroSection />
      <ComparisonTable />
      <ComparisonCards />
      <CTASection />
    </>
  );
}
