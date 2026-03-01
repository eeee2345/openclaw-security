import { getTranslations } from 'next-intl/server';
import RegisterForm from './RegisterForm';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('register.title'),
    description: t('register.description'),
  };
}

export default function RegisterPage() {
  return <RegisterForm />;
}
