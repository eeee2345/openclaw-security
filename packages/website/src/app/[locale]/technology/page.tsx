import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import TechnologyContent from './TechnologyContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('technology.title'),
    description: t('technology.description'),
  };
}

export default function TechnologyPage() {
  return (
    <>
      <NavBar />
      <main>
        <TechnologyContent />
      </main>
      <Footer />
    </>
  );
}
