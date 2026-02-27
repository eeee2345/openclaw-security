import { getTranslations } from 'next-intl/server';
import DevelopersContent from './DevelopersContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('developers.title'),
    description: t('developers.description'),
  };
}

export default function DevelopersPage() {
  return <DevelopersContent />;
}
