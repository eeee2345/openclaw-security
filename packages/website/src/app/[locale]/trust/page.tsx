import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import TrustContent from './TrustContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('trust.title'),
    description: t('trust.description'),
  };
}

export default function TrustPage() {
  return (
    <>
      <NavBar />
      <main>
        <TrustContent />
      </main>
      <Footer />
    </>
  );
}
