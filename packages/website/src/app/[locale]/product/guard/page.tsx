import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductGuardContent from './ProductGuardContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productGuard.title'),
    description: t('productGuard.description'),
    alternates: buildAlternates('/product/guard', params.locale),
  };
}

export default function ProductGuardPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ProductGuardContent />
      </main>
      <Footer />
    </>
  );
}
