import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import IntegrationsContent from './IntegrationsContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('integrations.title'),
    description: t('integrations.description'),
  };
}

export default function IntegrationsPage() {
  return (
    <>
      <NavBar />
      <main>
        <IntegrationsContent />
      </main>
      <Footer />
    </>
  );
}
