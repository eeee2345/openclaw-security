import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductScanContent from './ProductScanContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productScan.title'),
    description: t('productScan.description'),
  };
}

export default function ProductScanPage() {
  return (
    <>
      <NavBar />
      <main>
        <ProductScanContent />
      </main>
      <Footer />
    </>
  );
}
