import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ResourcesContent from './ResourcesContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('resources.title'),
    description: t('resources.description'),
    alternates: buildAlternates('/resources', params.locale),
  };
}

export default function ResourcesPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ResourcesContent />
      </main>
      <Footer />
    </>
  );
}
