import type { Metadata } from 'next';
import LoginForm from './LoginForm';

export const metadata: Metadata = {
  title: 'Log In | Panguard AI',
  description: 'Log in to your Panguard AI account.',
};

export default function LoginPage() {
  return <LoginForm />;
}
