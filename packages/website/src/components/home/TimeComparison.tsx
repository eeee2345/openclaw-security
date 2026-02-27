'use client';
import { useTranslations } from 'next-intl';
import SectionWrapper from '../ui/SectionWrapper';
import SectionTitle from '../ui/SectionTitle';
import FadeInUp from '../FadeInUp';

const ROW_COUNT = 6;

export default function TimeComparison() {
  const t = useTranslations('home.timeComparison');

  return (
    <SectionWrapper dark>
      <SectionTitle overline={t('overline')} title={t('title')} subtitle={t('subtitle')} />

      <FadeInUp>
        <div className="mt-14 max-w-3xl mx-auto overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 pr-4 text-text-muted font-medium w-1/3" />
                <th className="text-left py-3 px-4 text-text-muted font-medium w-1/3">
                  {t('colWithout')}
                </th>
                <th className="text-left py-3 pl-4 text-brand-sage font-medium w-1/3">
                  {t('colWith')}
                </th>
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: ROW_COUNT }).map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  <td className="py-3.5 pr-4 text-text-primary font-medium">
                    {t(`rows.${i}.label`)}
                  </td>
                  <td className="py-3.5 px-4 text-text-tertiary">{t(`rows.${i}.without`)}</td>
                  <td className="py-3.5 pl-4 text-status-safe font-medium">
                    {t(`rows.${i}.with`)}
                  </td>
                </tr>
              ))}
              <tr className="border-t-2 border-brand-sage/30">
                <td className="py-4 pr-4 text-text-primary font-bold">{t('costRow.label')}</td>
                <td className="py-4 px-4 text-text-tertiary">{t('costRow.without')}</td>
                <td className="py-4 pl-4 text-brand-sage font-bold text-lg">{t('costRow.with')}</td>
              </tr>
            </tbody>
          </table>
          <p className="text-xs text-text-muted mt-4">{t('source')}</p>
          <p className="text-sm text-text-secondary text-center mt-6 font-medium">
            {t('bottomLine')}
          </p>
        </div>
      </FadeInUp>
    </SectionWrapper>
  );
}
