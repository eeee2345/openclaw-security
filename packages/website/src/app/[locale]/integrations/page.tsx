import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import IntegrationsContent from './IntegrationsContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('integrations.title'),
    description: t('integrations.description'),
    alternates: buildAlternates('/integrations', params.locale),
  };
}

export default function IntegrationsPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <IntegrationsContent />
      </main>
      <Footer />
    </>
  );
}
