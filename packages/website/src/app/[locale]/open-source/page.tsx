import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import OpenSourceContent from './OpenSourceContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('openSource.title'),
    description: t('openSource.description'),
  };
}

export default function OpenSourcePage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <OpenSourceContent />
      </main>
      <Footer />
    </>
  );
}
