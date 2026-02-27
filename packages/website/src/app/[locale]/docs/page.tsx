import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import DocsContent from './DocsContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('docs.title'),
    description: t('docs.description'),
  };
}

export default function DocsPage() {
  return (
    <>
      <NavBar />
      <main>
        <DocsContent />
      </main>
      <Footer />
    </>
  );
}
