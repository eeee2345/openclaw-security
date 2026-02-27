import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import StatusContent from './StatusContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('status.title'),
    description: t('status.description'),
  };
}

export default function StatusPage() {
  return (
    <>
      <NavBar />
      <main>
        <StatusContent />
      </main>
      <Footer />
    </>
  );
}
