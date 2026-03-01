import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import GettingStartedContent from './GettingStartedContent';

export const metadata: Metadata = {
  title: 'Getting Started — Panguard AI',
  description:
    'Install Panguard AI in under 2 minutes. Quick-start guide for CLI setup, first scan, and 24/7 monitoring.',
  openGraph: {
    title: 'Getting Started — Panguard AI',
    description: 'Install and configure Panguard AI endpoint security in minutes.',
  },
};

export default function GettingStartedPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <GettingStartedContent />
      </main>
      <Footer />
    </>
  );
}
