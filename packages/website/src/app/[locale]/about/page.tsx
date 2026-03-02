import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import AboutContent from './AboutContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('about.title'),
    description: t('about.description'),
    alternates: buildAlternates('/about', params.locale),
  };
}

export default function AboutPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <AboutContent />
      </main>
      <Footer />
    </>
  );
}
