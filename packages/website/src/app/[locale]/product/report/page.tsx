import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductReportContent from './ProductReportContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productReport.title'),
    description: t('productReport.description'),
  };
}

export default function ProductReportPage() {
  return (
    <>
      <NavBar />
      <main>
        <ProductReportContent />
      </main>
      <Footer />
    </>
  );
}
