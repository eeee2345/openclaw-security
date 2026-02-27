import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import PressContent from './PressContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('press.title'),
    description: t('press.description'),
  };
}

export default function PressPage() {
  return (
    <>
      <NavBar />
      <main>
        <PressContent />
      </main>
      <Footer />
    </>
  );
}
