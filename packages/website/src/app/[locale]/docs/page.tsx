import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import DocsContent from './DocsContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('docs.title'),
    description: t('docs.description'),
    alternates: buildAlternates('/docs', params.locale),
  };
}

export default function DocsPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <DocsContent />
      </main>
      <Footer />
    </>
  );
}
