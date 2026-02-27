import { getTranslations } from 'next-intl/server';
import SMBContent from './SMBContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('smb.title'),
    description: t('smb.description'),
  };
}

export default function SMBPage() {
  return <SMBContent />;
}
