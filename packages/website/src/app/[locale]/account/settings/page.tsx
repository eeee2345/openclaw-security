import type { Metadata } from 'next';
import AccountSettings from './AccountSettings';

export const metadata: Metadata = {
  title: 'Account Settings | Panguard AI',
  description: 'Manage your Panguard AI account settings.',
};

export default function AccountSettingsPage() {
  return <AccountSettings />;
}
