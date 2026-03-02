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

const howToJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'HowTo',
  name: 'How to Install Panguard AI',
  description:
    'Install Panguard AI endpoint security in under 2 minutes. One command for Linux, macOS, or Windows.',
  totalTime: 'PT2M',
  step: [
    {
      '@type': 'HowToStep',
      name: 'Install Panguard CLI',
      text: 'Run the install script: curl -fsSL https://get.panguard.ai | sh',
      url: 'https://panguard.ai/docs/getting-started',
    },
    {
      '@type': 'HowToStep',
      name: 'Run your first scan',
      text: 'Execute panguard scan to perform a free 60-second security audit of your system.',
      url: 'https://panguard.ai/docs/getting-started',
    },
    {
      '@type': 'HowToStep',
      name: 'Enable 24/7 monitoring',
      text: 'Run panguard guard to activate the real-time AI protection agent.',
      url: 'https://panguard.ai/docs/getting-started',
    },
  ],
};

export default function GettingStartedPage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(howToJsonLd) }}
      />
      <NavBar />
      <main id="main-content">
        <GettingStartedContent />
      </main>
      <Footer />
    </>
  );
}
