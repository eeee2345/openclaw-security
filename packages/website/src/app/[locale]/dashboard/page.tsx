import { getTranslations } from 'next-intl/server';
import DashboardContent from './DashboardContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('dashboard.title'),
    description: t('dashboard.description'),
    robots: 'noindex',
  };
}

export default function DashboardPage() {
  return <DashboardContent />;
}
