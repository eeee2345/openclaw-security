import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import PartnersContent from './PartnersContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('partners.title'),
    description: t('partners.description'),
  };
}

export default function PartnersPage() {
  return (
    <>
      <NavBar />
      <main>
        <PartnersContent />
      </main>
      <Footer />
    </>
  );
}
