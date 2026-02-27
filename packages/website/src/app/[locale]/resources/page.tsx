import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ResourcesContent from './ResourcesContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('resources.title'),
    description: t('resources.description'),
  };
}

export default function ResourcesPage() {
  return (
    <>
      <NavBar />
      <main>
        <ResourcesContent />
      </main>
      <Footer />
    </>
  );
}
