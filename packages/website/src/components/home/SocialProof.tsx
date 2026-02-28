'use client';
import { useTranslations } from 'next-intl';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';
import CountUp from '../animations/CountUp';
import {
  ShieldIcon,
  NetworkIcon,
  TerminalIcon,
  ScanIcon,
  LockIcon,
  AnalyticsIcon,
  ReportIcon,
  ChatIcon,
} from '@/components/ui/BrandIcons';

export default function SocialProof() {
  const t = useTranslations('home.socialProof');

  const stats: Array<{
    numericValue?: number;
    textValue?: string;
    suffix?: string;
    label: string;
    icon: typeof ShieldIcon;
  }> = [
    { numericValue: 3158, label: t('stat1Label'), icon: ScanIcon },
    { numericValue: 425, label: t('stat2Label'), icon: TerminalIcon },
    { numericValue: 8, label: t('stat3Label'), icon: NetworkIcon },
    { numericValue: 1107, label: t('stat4Label'), icon: ShieldIcon },
    { textValue: '4+1', label: t('stat5Label'), icon: AnalyticsIcon },
    { numericValue: 5, label: t('stat6Label'), icon: ChatIcon },
    { numericValue: 6, label: t('stat7Label'), icon: ReportIcon },
    { textValue: 'MIT', label: t('stat8Label'), icon: LockIcon },
  ];

  return (
    <SectionWrapper>
      <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-14 max-w-4xl mx-auto">
        {stats.map((s, i) => (
          <FadeInUp key={s.label} delay={i * 0.05}>
            <div className="bg-surface-1 rounded-xl border border-border p-5 text-center card-glow">
              <s.icon size={20} className="text-brand-sage mx-auto mb-3" />
              <p className="text-2xl sm:text-3xl font-extrabold text-text-primary">
                {s.numericValue !== null && s.numericValue !== undefined ? (
                  <CountUp target={s.numericValue} suffix={s.suffix} />
                ) : (
                  s.textValue
                )}
              </p>
              <p className="text-xs text-text-tertiary mt-2">{s.label}</p>
            </div>
          </FadeInUp>
        ))}
      </div>

      <FadeInUp delay={0.4}>
        <p className="text-xs text-text-muted text-center mt-8 max-w-xl mx-auto leading-relaxed">
          {t('footnote')}{' '}
          <a
            href="https://github.com/panguard-ai/panguard-ai"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-sage hover:underline"
          >
            {t('githubLink')}
          </a>
        </p>
      </FadeInUp>
    </SectionWrapper>
  );
}
