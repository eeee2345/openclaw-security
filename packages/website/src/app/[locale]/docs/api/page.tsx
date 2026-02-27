import type { Metadata } from 'next';
import ComingSoon from '@/components/ComingSoon';

export const metadata: Metadata = {
  title: 'API Reference | Panguard AI',
  description:
    'Panguard AI REST API documentation for integrating automated security scanning, threat intelligence, and compliance reporting into your workflow.',
};

export default function ApiDocsPage() {
  return <ComingSoon title="API Reference" />;
}
