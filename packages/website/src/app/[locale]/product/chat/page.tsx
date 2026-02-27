import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ProductChatContent from './ProductChatContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('productChat.title'),
    description: t('productChat.description'),
  };
}

export default function ProductChatPage() {
  return (
    <>
      <NavBar />
      <main>
        <ProductChatContent />
      </main>
      <Footer />
    </>
  );
}
