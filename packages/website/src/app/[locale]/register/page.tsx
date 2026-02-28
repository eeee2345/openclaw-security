import type { Metadata } from 'next';
import RegisterForm from './RegisterForm';

export const metadata: Metadata = {
  title: 'Create Account | Panguard AI',
  description: 'Create your Panguard AI account.',
};

export default function RegisterPage() {
  return <RegisterForm />;
}
