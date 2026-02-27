import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import CompanyContent from './CompanyContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('company.title'),
    description: t('company.description'),
  };
}

export default function CompanyPage() {
  return (
    <>
      <NavBar />
      <main>
        <CompanyContent />
      </main>
      <Footer />
    </>
  );
}
