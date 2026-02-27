import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import SecurityContent from './SecurityContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('security.title'),
    description: t('security.description'),
  };
}

export default function SecurityPage() {
  return (
    <>
      <NavBar />
      <main>
        <SecurityContent />
      </main>
      <Footer />
    </>
  );
}
