import { getTranslations } from 'next-intl/server';
import AccountSettings from './AccountSettings';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('accountSettings.title'),
    description: t('accountSettings.description'),
    robots: 'noindex',
  };
}

export default function AccountSettingsPage() {
  return <AccountSettings />;
}
