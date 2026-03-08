import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ATRContent from './ATRContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('atr.title'),
    description: t('atr.description'),
    alternates: buildAlternates('/atr', params.locale),
  };
}

export default function ATRPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ATRContent />
      </main>
      <Footer />
    </>
  );
}
