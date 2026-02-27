import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import WaitlistForm from './WaitlistForm';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('earlyAccess.title'),
    description: t('earlyAccess.description'),
  };
}

/* ════════════════════════  Config  ═══════════════════════ */

const benefitKeys = ['priority', 'feedback', 'founding'] as const;

const timelineSteps = [
  { phaseKey: 'now' as const, labelKey: 'nowLabel' as const },
  { phaseKey: 'q2' as const, labelKey: 'q2Label' as const },
  { phaseKey: 'q3' as const, labelKey: 'q3Label' as const },
];

/* ════════════════════════  Page Component  ═══════════════════════ */

export default async function EarlyAccessPage({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'earlyAccess' });

  return (
    <>
      <NavBar />
      <main>
        {/* ───────────── Hero ───────────── */}
        <section className="pt-24 pb-4 px-6 text-center">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('overline')}
            </p>
            <h1 className="text-[clamp(40px,5vw,64px)] font-bold text-text-primary leading-[1.08] max-w-3xl mx-auto">
              {t('title1')}
              <br />
              <span className="text-brand-sage">{t('title2')}</span>
            </h1>
            <p className="text-text-secondary mt-4 text-lg max-w-xl mx-auto leading-relaxed">
              {t('subtitle')}
            </p>
          </FadeInUp>
        </section>

        {/* ───────────── Form Section ───────────── */}
        <SectionWrapper>
          <WaitlistForm />
        </SectionWrapper>

        {/* ───────────── What You Get ───────────── */}
        <SectionWrapper dark>
          <FadeInUp>
            <div className="max-w-3xl mx-auto">
              <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1] text-center">
                {t('whatYouGet')}
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12">
                {benefitKeys.map((key) => (
                  <div key={key} className="bg-surface-0 rounded-2xl border border-border p-6">
                    <div className="w-2 h-2 rounded-full bg-brand-sage mb-4" />
                    <h3 className="text-text-primary font-semibold mb-2">{t(key)}</h3>
                    <p className="text-sm text-text-secondary leading-relaxed">{t(`${key}Desc`)}</p>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
        </SectionWrapper>

        {/* ───────────── Timeline ───────────── */}
        <SectionWrapper>
          <FadeInUp>
            <div className="max-w-2xl mx-auto text-center">
              <h2 className="text-[clamp(24px,3vw,32px)] font-bold text-text-primary leading-[1.1]">
                {t('timeline')}
              </h2>
              <div className="mt-10 space-y-0">
                {timelineSteps.map((step, i) => (
                  <div key={step.phaseKey} className="flex items-start gap-4">
                    <div className="flex flex-col items-center">
                      <div
                        className={`w-3 h-3 rounded-full ${
                          i === 0 ? 'bg-brand-sage' : 'bg-surface-2 border border-border'
                        }`}
                      />
                      {i < 2 && <div className="w-px h-10 bg-border" />}
                    </div>
                    <div className="pb-6">
                      <p className="text-xs uppercase tracking-wider text-brand-sage font-semibold">
                        {t(step.phaseKey)}
                      </p>
                      <p className="text-text-secondary text-sm mt-1">{t(step.labelKey)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </FadeInUp>
        </SectionWrapper>
      </main>
      <Footer />
    </>
  );
}
