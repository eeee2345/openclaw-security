import type { Metadata } from 'next';
import ResetPasswordForm from './ResetPasswordForm';

export const metadata: Metadata = {
  title: 'Reset Password | Panguard AI',
  description: 'Set a new password for your Panguard AI account.',
};

export default function ResetPasswordPage() {
  return <ResetPasswordForm />;
}
