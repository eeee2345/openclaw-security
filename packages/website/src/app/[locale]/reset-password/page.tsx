import { getTranslations } from 'next-intl/server';
import ResetPasswordForm from './ResetPasswordForm';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('resetPassword.title'),
    description: t('resetPassword.description'),
  };
}

export default function ResetPasswordPage() {
  return <ResetPasswordForm />;
}
