import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ChangelogContent from './ChangelogContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('changelog.title'),
    description: t('changelog.description'),
  };
}

export default function ChangelogPage() {
  return (
    <>
      <NavBar />
      <main>
        <ChangelogContent />
      </main>
      <Footer />
    </>
  );
}
