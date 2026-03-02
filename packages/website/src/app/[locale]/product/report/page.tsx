import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductReportContent from './ProductReportContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productReport.title'),
    description: t('productReport.description'),
    alternates: buildAlternates('/product/report', params.locale),
  };
}

export default function ProductReportPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ProductReportContent />
      </main>
      <Footer />
    </>
  );
}
