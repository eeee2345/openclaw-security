import type { Metadata } from 'next';
import BillingContent from './BillingContent';

export const metadata: Metadata = {
  title: 'Billing | Panguard AI',
  description: 'Manage your Panguard AI subscription and billing.',
};

export default function BillingPage() {
  return <BillingContent />;
}
