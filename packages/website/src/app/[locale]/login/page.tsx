import { getTranslations } from 'next-intl/server';
import LoginForm from './LoginForm';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('login.title'),
    description: t('login.description'),
    robots: { index: false, follow: false },
  };
}

export default function LoginPage() {
  return <LoginForm />;
}
