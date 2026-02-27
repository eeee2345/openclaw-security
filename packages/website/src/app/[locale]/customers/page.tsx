import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CustomersContent from './CustomersContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('customers.title'),
    description: t('customers.description'),
  };
}

export default function CustomersPage() {
  return (
    <>
      <NavBar />
      <main>
        <CustomersContent />
      </main>
      <Footer />
    </>
  );
}
