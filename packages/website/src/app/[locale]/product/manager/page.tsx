import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductManagerContent from './ProductManagerContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productManager.title'),
    description: t('productManager.description'),
    alternates: buildAlternates('/product/manager', params.locale),
  };
}

export default function ProductManagerPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ProductManagerContent />
      </main>
      <Footer />
    </>
  );
}
