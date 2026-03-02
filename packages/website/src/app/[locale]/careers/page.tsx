import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CareersContent from './CareersContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('careers.title'),
    description: t('careers.description'),
    alternates: buildAlternates('/careers', params.locale),
  };
}

export default function CareersPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <CareersContent />
      </main>
      <Footer />
    </>
  );
}
