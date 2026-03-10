import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import FadeInUp from '@/components/FadeInUp';
import SectionWrapper from '@/components/ui/SectionWrapper';
import SectionTitle from '@/components/ui/SectionTitle';
import FAQAccordion from './FAQAccordion';
import PricingCards from './PricingCards';
import { ShieldIcon } from '@/components/ui/BrandIcons';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('pricing.title'),
    description: t('pricing.description'),
    alternates: buildAlternates('/pricing', params.locale),
    openGraph: {
      title: t('pricing.title'),
      description: t('pricing.description'),
      images: [{ url: '/og-image.png', width: 1200, height: 630 }],
    },
  };
}

const faqKeys = ['faq1', 'faq2', 'faq3', 'faq4', 'faq5'] as const;

export default async function PricingPage() {
  const t = await getTranslations('pricingPage');

  const faqJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: faqKeys.map((key) => ({
      '@type': 'Question',
      name: t(`faq.${key}q`),
      acceptedAnswer: {
        '@type': 'Answer',
        text: t(`faq.${key}a`),
      },
    })),
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqJsonLd) }}
      />
      <NavBar />
      <main id="main-content">
        {/* Hero */}
        <section className="pt-24 pb-4 px-6 text-center">
          <FadeInUp>
            <p className="text-[11px] uppercase tracking-[0.12em] text-brand-sage font-semibold mb-4">
              {t('hero.overline')}
            </p>
            <h1 className="text-[clamp(30px,5vw,64px)] font-bold text-text-primary leading-[1.08] max-w-3xl mx-auto">
              {t('hero.title')}
            </h1>
            <p className="text-text-secondary mt-4 text-lg max-w-xl mx-auto leading-relaxed">
              {t('hero.subtitle')}
            </p>
          </FadeInUp>
        </section>

        {/* Pricing Card */}
        <SectionWrapper>
          <PricingCards />
        </SectionWrapper>

        {/* FAQ */}
        <SectionWrapper dark>
          <SectionTitle
            overline={t('faqSection.overline')}
            title={t('faqSection.title')}
            subtitle={t('faqSection.subtitle')}
          />
          <div className="mt-12 max-w-2xl mx-auto">
            <FAQAccordion />
          </div>
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
