import type { Metadata } from 'next';
import BlogAdminContent from './BlogAdminContent';

export const metadata: Metadata = {
  title: 'Blog Admin | Panguard AI',
  robots: 'noindex',
};

export default function BlogAdminPage() {
  return <BlogAdminContent />;
}
