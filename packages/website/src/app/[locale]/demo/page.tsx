import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import DemoContent from './DemoContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('demo.title'),
    description: t('demo.description'),
    alternates: buildAlternates('/demo', params.locale),
  };
}

export default function DemoPage() {
  return <DemoContent />;
}
