import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ThreatCloudContent from './ThreatCloudContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('threatCloud.title'),
    description: t('threatCloud.description'),
  };
}

export default function ThreatCloudPage() {
  return (
    <>
      <NavBar />
      <main>
        <ThreatCloudContent />
      </main>
      <Footer />
    </>
  );
}
