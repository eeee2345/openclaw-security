import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ComplianceContent from './ComplianceContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('compliance.title'),
    description: t('compliance.description'),
  };
}

export default function CompliancePage() {
  return (
    <>
      <NavBar />
      <main>
        <ComplianceContent />
      </main>
      <Footer />
    </>
  );
}
