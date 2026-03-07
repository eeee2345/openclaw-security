import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import GuardDocsContent from './GuardDocsContent';

export const metadata: Metadata = {
  title: 'Panguard Guard — Documentation',
  description: 'Real-time endpoint protection with 5-agent AI pipeline. Configure detection rules, response actions, and threat monitoring.',
  openGraph: {
    title: 'Panguard Guard — Panguard AI Docs',
    description: '24/7 endpoint protection: Sigma + YARA + ATR rules, AI analysis, automated response.',
  },
};

export default function GuardDocsPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <GuardDocsContent />
      </main>
      <Footer />
    </>
  );
}
