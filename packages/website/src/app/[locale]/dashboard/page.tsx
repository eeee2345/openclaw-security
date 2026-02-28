import type { Metadata } from 'next';
import DashboardContent from './DashboardContent';

export const metadata: Metadata = {
  title: 'Dashboard | Panguard AI',
  description: 'Your Panguard AI dashboard.',
};

export default function DashboardPage() {
  return <DashboardContent />;
}
