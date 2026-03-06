import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductMcpContent from './ProductMcpContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productMcp.title'),
    description: t('productMcp.description'),
    alternates: buildAlternates('/product/mcp', params.locale),
  };
}

export default function ProductMcpPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ProductMcpContent />
      </main>
      <Footer />
    </>
  );
}
