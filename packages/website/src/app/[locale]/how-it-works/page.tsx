import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import HowItWorksContent from './HowItWorksContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('howItWorks.title'),
    description: t('howItWorks.description'),
  };
}

export default function HowItWorksPage() {
  return (
    <>
      <NavBar />
      <main>
        <HowItWorksContent />
      </main>
      <Footer />
    </>
  );
}
