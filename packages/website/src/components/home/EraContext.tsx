'use client';
import { useTranslations } from 'next-intl';
import SectionWrapper from '../ui/SectionWrapper';
import FadeInUp from '../FadeInUp';

export default function EraContext() {
  const t = useTranslations('home.eraContext');
  return (
    <SectionWrapper dark>
      <div className="max-w-3xl mx-auto text-center">
        <FadeInUp>
          <h2 className="text-[clamp(28px,4vw,40px)] font-bold text-text-primary leading-[1.2]">
            {t('title')}
          </h2>
        </FadeInUp>
        <FadeInUp delay={0.1}>
          <div className="mt-8 space-y-3">
            <p className="text-lg text-text-secondary leading-relaxed">{t('desc1')}</p>
            <p className="text-lg text-text-secondary leading-relaxed">{t('desc2')}</p>
            <p className="text-lg text-text-primary font-semibold leading-relaxed">{t('desc3')}</p>
            <p className="text-lg text-brand-sage font-semibold leading-relaxed">{t('desc4')}</p>
          </div>
        </FadeInUp>
      </div>
    </SectionWrapper>
  );
}
