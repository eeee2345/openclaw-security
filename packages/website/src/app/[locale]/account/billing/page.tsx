import { getTranslations } from 'next-intl/server';
import BillingContent from './BillingContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('billing.title'),
    description: t('billing.description'),
    robots: 'noindex',
  };
}

export default function BillingPage() {
  return <BillingContent />;
}
