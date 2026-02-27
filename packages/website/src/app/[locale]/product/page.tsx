import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductOverviewContent from './ProductOverviewContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productOverview.title'),
    description: t('productOverview.description'),
  };
}

export default function ProductPage() {
  return (
    <>
      <NavBar />
      <main>
        <ProductOverviewContent />
      </main>
      <Footer />
    </>
  );
}
