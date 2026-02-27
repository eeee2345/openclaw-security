import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import FAQAccordion from './FAQAccordion';
import PricingCards from './PricingCards';
import { ShieldIcon, EnterpriseIcon, CheckIcon } from '@/components/ui/BrandIcons';
import { Link } from '@/navigation';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('pricing.title'),
    description: t('pricing.description'),
  };
}

export default async function PricingPage() {
  const t = await getTranslations('pricingPage');

  return (
    <>
      <NavBar />
      <main>
        {/* Hero */}
        <section className="pt-24 pb-4 px-6 text-center">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('hero.overline')}
            </p>
            <h1 className="text-[clamp(40px,5vw,64px)] font-bold text-text-primary leading-[1.08] max-w-3xl mx-auto">
              {t('hero.title')}
            </h1>
            <p className="text-text-secondary mt-4 text-lg max-w-xl mx-auto leading-relaxed">
              {t('hero.subtitle')}
            </p>
          </FadeInUp>
        </section>

        {/* Pricing Cards (client component with toggle) */}
        <SectionWrapper>
          <PricingCards />
        </SectionWrapper>

        {/* Compliance Add-ons */}
        <SectionWrapper dark>
          <SectionTitle
            overline={t('addons.overline')}
            title={t('addons.title')}
            subtitle={t('addons.subtitle')}
          />
          <FadeInUp>
            <div className="grid sm:grid-cols-2 gap-6 mt-10 max-w-3xl mx-auto">
              {(['assessment', 'monitoring'] as const).map((key) => {
                const includes = t.raw(`addons.${key}.includes`) as string[];
                const frameworks = t.raw(`addons.${key}.frameworks`) as string[];
                return (
                  <div key={key} className="bg-surface-2 rounded-xl border border-border p-6">
                    <p className="text-sm font-bold text-text-primary mb-1">
                      {t(`addons.${key}.name`)}
                    </p>
                    <div className="flex items-baseline gap-2 mb-1">
                      <span className="text-3xl font-extrabold text-brand-sage">
                        {t(`addons.${key}.price`)}
                      </span>
                      <span className="text-sm text-text-muted line-through">
                        {t(`addons.${key}.originalPrice`)}
                      </span>
                      <span className="text-xs text-text-tertiary">{t(`addons.${key}.unit`)}</span>
                    </div>
                    <p className="text-[10px] text-brand-sage mb-3">
                      {t(`addons.${key}.earlyBird`)}
                    </p>
                    <p className="text-xs text-text-secondary mb-2">{t(`addons.${key}.desc`)}</p>
                    <div className="flex flex-wrap gap-1.5 mb-4">
                      {frameworks.map((fw: string) => (
                        <span
                          key={fw}
                          className="text-[10px] bg-surface-0 border border-border rounded-full px-2 py-0.5 text-text-tertiary"
                        >
                          {fw}
                        </span>
                      ))}
                    </div>
                    <ul className="space-y-1.5">
                      {includes.map((item: string) => (
                        <li
                          key={item}
                          className="flex items-start gap-2 text-xs text-text-secondary"
                        >
                          <CheckIcon className="w-3.5 h-3.5 text-brand-sage mt-0.5 shrink-0" />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
            </div>
            <p className="text-xs text-text-muted text-center mt-4">{t('addons.requiresPro')}</p>
            <p className="text-[10px] text-text-muted text-center mt-3 max-w-2xl mx-auto leading-relaxed">
              {t('addons.disclaimer')}
            </p>
          </FadeInUp>
        </SectionWrapper>

        {/* FAQ */}
        <SectionWrapper>
          <SectionTitle
            overline={t('faqSection.overline')}
            title={t('faqSection.title')}
            subtitle={t('faqSection.subtitle')}
          />
          <div className="mt-12 max-w-2xl mx-auto">
            <FAQAccordion />
          </div>
        </SectionWrapper>

        {/* Enterprise CTA */}
        <SectionWrapper dark>
          <FadeInUp>
            <div className="text-center max-w-2xl mx-auto">
              <EnterpriseIcon className="w-10 h-10 text-brand-sage mx-auto mb-6" />
              <h2 className="text-[clamp(28px,3.5vw,40px)] font-bold text-text-primary leading-[1.1]">
                {t('enterprise.title')}
              </h2>
              <p className="text-text-secondary mt-4 leading-relaxed">{t('enterprise.desc')}</p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
                <Link
                  href="/contact"
                  className="bg-brand-sage text-surface-0 font-semibold rounded-full px-8 py-3 hover:bg-brand-sage-light transition-all duration-200 active:scale-[0.98]"
                >
                  {t('enterprise.ctaSales')}
                </Link>
                <Link
                  href="/demo"
                  className="border border-border text-text-secondary font-semibold rounded-full px-8 py-3 hover:border-brand-sage hover:text-text-primary transition-all duration-200"
                >
                  {t('enterprise.ctaDemo')}
                </Link>
              </div>
            </div>
          </FadeInUp>
        </SectionWrapper>

        {/* Guarantee */}
        <section className="py-10 px-6 text-center border-b border-border">
          <FadeInUp>
            <div className="flex items-center justify-center gap-2">
              <ShieldIcon className="w-4 h-4 text-brand-sage" />
              <p className="text-sm text-text-tertiary">{t('guarantee')}</p>
            </div>
          </FadeInUp>
        </section>
      </main>
      <Footer />
    </>
  );
}
