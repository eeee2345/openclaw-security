import { getTranslations } from 'next-intl/server';
import { buildAlternates } from '@/lib/seo';
import ContactContent from './ContactContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('contact.title'),
    description: t('contact.description'),
    alternates: buildAlternates('/contact', params.locale),
  };
}

export default function ContactPage() {
  return <ContactContent />;
}
