import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import EnterpriseContent from './EnterpriseContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('enterprise.title'),
    description: t('enterprise.description'),
    alternates: buildAlternates('/solutions/enterprise', params.locale),
  };
}

export default function EnterprisePage() {
  return <EnterpriseContent />;
}
